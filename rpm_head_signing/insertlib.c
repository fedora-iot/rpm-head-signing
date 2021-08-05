#include <Python.h>

#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include <rpm/rpmtypes.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmfi.h>

// Functions that are in librpm but are not in the headers
// This one function is identical from 4.11 onwards...
int rpmWriteSignature(FD_t fd, Header sigh);

#if defined(RPM_415)

    // There are 4.15 versions that don't have this define
    #define RPMTAG_PAYLOADDIGESTALT 5097

    rpmRC rpmLeadRead(FD_t fd, char **emsg);
    rpmRC rpmLeadWrite(FD_t fd, Header h);
    rpmRC rpmReadSignature(FD_t fd, Header * sighp, char ** msg);

#elif defined(RPM_414)

    #define RPMTAG_PAYLOADDIGESTALT 5097
    #define RPMSIGTAG_FILESIGNATURES RPMTAG_SIG_BASE + 18
    #define RPMSIGTAG_FILESIGNATURELENGTH RPMTAG_SIG_BASE 19

    rpmRC rpmLeadRead(FD_t fd, int *type, char **emsg);
    rpmRC rpmLeadWrite(FD_t fd, Header h);
    rpmRC rpmReadSignature(FD_t fd, Header * sighp, char ** msg);

#elif defined(RPM_411)

    #define RPMTAG_FILESIGNATURES 5090
    #define RPMTAG_FILESIGNATURELENGTH 5091
    #define RPMTAG_PAYLOADDIGEST 5092
    #define RPMSIGTAG_RESERVEDSPACE 1008

    #define RPMTAG_PAYLOADDIGESTALT 5097
    #define RPMSIGTAG_FILESIGNATURES RPMTAG_SIG_BASE + 18
    #define RPMSIGTAG_FILESIGNATURELENGTH RPMTAG_SIG_BASE 19

    struct rpmlead_s {
        unsigned char magic[4];
        unsigned char major;
        unsigned char minor;
        short type;
        short archnum;
        char name[66];
        short osnum;
        short signature_type;       /*!< Signature header type (RPMSIG_HEADERSIG) */
        char reserved[16];      /*!< Pad to 96 bytes -- 8 byte aligned! */
    };
    typedef struct rpmlead_s * rpmlead;

    rpmlead rpmLeadFromHeader(Header h);
    rpmlead rpmLeadFree(rpmlead lead);

    typedef enum sigType_e {
        RPMSIGTYPE_HEADERSIG= 5     /*!< Header style signature */
    } sigType;

    rpmRC rpmReadSignature(FD_t fd, Header *sighp, sigType sig_type, char ** msg);
    rpmRC rpmLeadWrite(FD_t fd, rpmlead lead);
    rpmRC rpmLeadRead(FD_t fd, rpmlead *lead, int *type, char **emsg);

#else
    #error "Please provide RPM version macro"
#endif

static void unloadImmutableRegion(Header *hdrp, rpmTagVal tag)
{
    struct rpmtd_s td;
    Header oh = NULL;

    if (headerGet(*hdrp, tag, &td, HEADERGET_DEFAULT)) {
        oh = headerImport(td.data, td.count, HEADERIMPORT_COPY);
        rpmtdFreeData(&td);
    } else {
        /* XXX should we warn if the immutable region is corrupt/missing? */
        oh = headerLink(*hdrp);
    }

    if (oh) {
        /* Perform a copy to eliminate crud from buggy signing tools etc */
        Header nh = headerCopy(oh);
        headerFree(*hdrp);
        *hdrp = headerLink(nh);
        headerFree(nh);
        headerFree(oh);
    }
}

static const char *hash_algo_names[] = {
    [PGPHASHALGO_MD5]          = "md5",
    [PGPHASHALGO_SHA1]         = "sha1",
    [PGPHASHALGO_RIPEMD160]    = "rmd160",
    [PGPHASHALGO_MD2]          = "md2",
    [PGPHASHALGO_TIGER192]     = "tgr192",
    [PGPHASHALGO_HAVAL_5_160]  = "haval5160",
    [PGPHASHALGO_SHA256]       = "sha256",
    [PGPHASHALGO_SHA384]       = "sha384",
    [PGPHASHALGO_SHA512]       = "sha512",
    [PGPHASHALGO_SHA224]       = "sha224",
};
#define ARRAY_SIZE(a)  (sizeof(a) / sizeof(a[0]))

static bool copyFile(FD_t *sfdp, FD_t *tfdp)
{
    unsigned char buf[BUFSIZ];
    ssize_t count;

    while ((count = Fread(buf, sizeof(buf[0]), sizeof(buf), *sfdp)) > 0)
    {
        if (Fwrite(buf, sizeof(buf[0]), count, *tfdp) != count) {
            PyErr_Format(PyExc_Exception, "Error writing to output file: %s", Fstrerror(*tfdp));
            return false;
        }
    }
    if (count < 0) {
        PyErr_Format(PyExc_Exception, "Error reading from source file: %s", Fstrerror(*sfdp));
        return false;
    }
    if (Fflush(*tfdp) != 0) {
        PyErr_Format(PyExc_Exception, "Error flushing output file: %s", Fstrerror(*tfdp));
        return false;
    }

    return true;
}

// Here start the functions I wrote from scratch
static bool
insert_ima_signatures(Header sigh, Header h, PyObject *ima_digest_lookup)
{
    struct rpmtd_s td;
    rpmfi fi = rpmfiNew(NULL, h, RPMTAG_BASENAMES, RPMFI_FLAGS_QUERY);
    rpmRC rc = RPMRC_FAIL;
    int siglen = 0;

    if (rpmfiFC(fi) == 0) {
        rc = RPMRC_OK;
        goto out;
    }

    long unsigned int algo = rpmfiDigestAlgo(fi);
    if (algo >= ARRAY_SIZE(hash_algo_names)) {
        PyErr_Format(PyExc_Exception, "Invalid digest algorithm ID: %d", (int)algo);
        goto out;
    }

    const char *algoname = hash_algo_names[algo];

    PyObject *ima_values_lookup = PyDict_GetItemString(ima_digest_lookup, algoname);
    if (ima_values_lookup == NULL) {
        PyErr_Format(PyExc_Exception, "No signatures in lookup for digest %s", algoname);
        goto out;
    }

    headerDel(sigh, RPMTAG_FILESIGNATURELENGTH);
    headerDel(sigh, RPMTAG_FILESIGNATURES);

    rpmtdReset(&td);
    td.tag = RPMSIGTAG_FILESIGNATURES;
    td.type = RPM_STRING_ARRAY_TYPE;
    td.data = NULL;  // Set below
    td.count = 1;

    while (rpmfiNext(fi) >= 0) {
        char *digest = rpmfiFDigestHex(fi, NULL);
        PyObject *signature = PyDict_GetItemString(ima_values_lookup, digest);
        if (signature == NULL) {
            PyErr_Format(PyExc_Exception, "File digest encountered for which no signature was found: %s", digest);
            free(digest);
            goto out;
        }
        free(digest);
        const char *sigstr = PyBytes_AsString(signature);
        if (sigstr == NULL) {
            // AsString sets the error
            goto out;
        }
        td.data = &sigstr;
        if (siglen == 0) {
            siglen = strlen(sigstr);
        }
        if (!headerPut(sigh, &td, HEADERPUT_APPEND)) {
            PyErr_SetString(PyExc_Exception, "Error appending file signature to sigheader");
            goto out;
        }
    }

    rc = RPMRC_OK;

out:
    rpmfiFree(fi);
    if (rc == RPMRC_OK) {
        return true;
    } else {
        return false;
    }
}

static PyObject *
insert_signatures(PyObject *self, PyObject *args)
{
    int return_header;
    PyObject *return_value = NULL;
    bool success = false;
    const char *rpm_path;
    PyObject *signature = NULL;
    PyObject *ima_lookup = NULL;
    PyObject *sig_hdr_magic = NULL;
    PyObject *sig_hdr = NULL;
    PyObject *sig_hdr_pad = NULL;
    PyObject *sig_hdr_padded = NULL;
    char *trpm = NULL;
    char *msg = NULL;
    FD_t rpm_fd = NULL;
    FD_t rpm_ofd = NULL;
    Header sigh = NULL;
    Header h = NULL;
    pgpDigParams sigp = NULL;
    rpmtd sigtd = NULL;
#ifdef RPM_411
    rpmlead lead = NULL;
#endif

    if (!PyArg_ParseTuple(args, "isO|O:insert_signatures", &return_header, &rpm_path, &signature, &ima_lookup))
        return NULL;

    if (signature == Py_None) {
        // We should not decrement the refcount of the in-arguments, so we can just set it to NULL
        signature = NULL;
    } else if (Py_TYPE(signature) != &PyByteArray_Type) {
        PyErr_SetString(PyExc_TypeError, "Signature is not None or ByteArray");
        goto out;
    }
    if (ima_lookup == Py_None || ima_lookup == NULL) {
        // We should not decrement the refcount of the in-arguments, so we can just set it to NULL
        ima_lookup = NULL;
    } else if (Py_TYPE(ima_lookup) != &PyDict_Type) {
        PyErr_SetString(PyExc_TypeError, "IMA lookup is not None or Dict");
        goto out;
    }

    if (signature == NULL && ima_lookup == NULL) {
        PyErr_SetString(PyExc_Exception, "No signature or ima_lookup provided");
        goto out;
    }

    rpm_fd = Fopen(rpm_path, "r+.ufdio");
    if (rpm_fd == NULL || Ferror(rpm_fd)) {
        PyErr_Format(PyExc_Exception, "Error opening RPM file: %s", Fstrerror(rpm_fd));
        goto out;
    }

#if defined(RPM_415)
    if (rpmLeadRead(rpm_fd, &msg) != RPMRC_OK) {
#elif defined(RPM_411)
    if (rpmLeadRead(rpm_fd, NULL, NULL, &msg) != RPMRC_OK) {
#else
    if (rpmLeadRead(rpm_fd, NULL, &msg) != RPMRC_OK) {
#endif
        PyErr_Format(PyExc_Exception, "Error leading read: %s", (msg && *msg ? msg : "Unknown error"));
        goto out;
    }

    off_t sigStart = Ftell(rpm_fd);
#ifdef RPM_411
    if (rpmReadSignature(rpm_fd, &sigh, RPMSIGTYPE_HEADERSIG, &msg) != RPMRC_OK) {
#else
    if (rpmReadSignature(rpm_fd, &sigh, &msg) != RPMRC_OK) {
#endif
        PyErr_Format(PyExc_Exception, "rpmReadSignature failed: %s", (msg && *msg ? msg : "Unknown error"));
        goto out;
    }

    off_t headerStart = Ftell(rpm_fd);
    if (rpmReadHeader(NULL, rpm_fd, &h, &msg) != RPMRC_OK) {
        PyErr_Format(PyExc_Exception, "rpmReadHeader failed: %s", (msg && *msg ? msg : "Unknown error"));
        goto out;
    }

    if (!headerIsEntry(h, RPMTAG_HEADERIMMUTABLE)) {
        PyErr_SetString(PyExc_Exception, "RPM v3 package encountered");
        goto out;
    }
    if (!(headerIsEntry(h, RPMTAG_PAYLOADDIGEST) ||
            headerIsEntry(h, RPMTAG_PAYLOADDIGESTALT))) {
        PyErr_SetString(PyExc_Exception, "RPM package without payload digest found");
        goto out;
    }

    unloadImmutableRegion(&sigh, RPMTAG_HEADERSIGNATURES);
#ifndef RPM_411
    unsigned int origSigSize = headerSizeof(sigh, HEADER_MAGIC_YES);
#endif

    if (signature != NULL) {
        // Insert v4 signature header
        const unsigned char *signature_buf = (unsigned char *)PyByteArray_AsString(signature);
        Py_ssize_t signature_len = PyByteArray_Size(signature);
        if (pgpPrtParams(signature_buf, signature_len, PGPTAG_SIGNATURE, &sigp) != RPMRC_OK) {
            PyErr_SetString(PyExc_Exception, "Unsupported PGP signature");
            goto out;
        }
        unsigned int pubkey_algo = pgpDigParamsAlgo(sigp, PGPVAL_PUBKEYALGO);
        rpmTagVal sigtag;
        switch (pubkey_algo) {
            case PGPPUBKEYALGO_DSA:
                sigtag = RPMSIGTAG_DSA;
                break;
            case PGPPUBKEYALGO_RSA:
                sigtag = RPMSIGTAG_RSA;
                break;
            default:
                PyErr_Format(PyExc_Exception, "Unsupported PGP signature algorithm %u", pubkey_algo);
                goto out;
        }

        sigtd = rpmtdNew();
        sigtd->count = signature_len;
        sigtd->data = malloc(signature_len);
        if (sigtd->data == NULL) {
            PyErr_SetString(PyExc_Exception, "Error allocating memory for signature copy");
            goto out;
        }
        memcpy(sigtd->data, signature_buf, signature_len);
        sigtd->type = RPM_BIN_TYPE;
        sigtd->tag = sigtag;
        sigtd->flags |= RPMTD_ALLOCED;

        // For some reason, rpmRC isn't used here, and 0 - failure, 1 - success
        if (headerPut(sigh, sigtd, HEADERPUT_DEFAULT) != 1) {
            PyErr_SetString(PyExc_Exception, "Error setting signature header");
            goto out;
        }
    }

    // Insert IMA signatures
    if (ima_lookup != NULL) {
        if (!insert_ima_signatures(sigh, h, ima_lookup)) {
            // This function sets its own exceptions
            goto out;
        }
    }

    // Clean out the reservedspace
    bool insSig = false;
    struct rpmtd_s utd;
    if (headerGet(sigh, RPMSIGTAG_RESERVEDSPACE, &utd, HEADERGET_MINMEM)) {
#ifdef RPM_411
        insSig = false;
        headerDel(sigh, RPMSIGTAG_RESERVEDSPACE);
#else
        unsigned int diff = headerSizeof(sigh, HEADER_MAGIC_YES) - origSigSize;

        if (diff > 0 && diff < utd.count) {
            utd.count -= diff;
            headerMod(sigh, &utd);
            insSig = true;
        } else {
            // If we were unable to reuse the existing reserved space, and have to rewrite
            // the entire file anyway, let's just get rid of the reserved space.
            headerDel(sigh, RPMSIGTAG_RESERVEDSPACE);
        }
#endif
    }

    // Reallocate signature into contiguous region
    sigh = headerReload(sigh, RPMTAG_HEADERSIGNATURES);
    if (sigh == NULL) {
        // Can't happen according to the comments...
        PyErr_SetString(PyExc_Exception, "HeaderReload failed");
        goto out;
    }

    if (return_header) {
        // Return the fully constructed signature header
        sig_hdr_magic = PyByteArray_FromStringAndSize((const char *)rpm_header_magic, 8);
        if (sig_hdr_magic == NULL) {
            PyErr_SetString(PyExc_Exception, "Error building bytearray from header magic");
            goto out;
        }
        unsigned int headerSize;
        void *headerBytes = headerExport(sigh, &headerSize);
        if (headerBytes == NULL) {
            PyErr_SetString(PyExc_Exception, "Error exporting header to bytearray");
            goto out;
        }
        sig_hdr = PyByteArray_FromStringAndSize(headerBytes, headerSize);
        free(headerBytes);
        if (sig_hdr == NULL) {
            PyErr_SetString(PyExc_Exception, "Error building bytearray from header");
            goto out;
        }

        static const char zeros[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        int padlen = (8 - (headerSize % 8)) % 8;
        if (padlen != 0) {
            sig_hdr_pad = PyByteArray_FromStringAndSize(zeros, padlen);
            if (sig_hdr_pad == NULL) {
                PyErr_SetString(PyExc_Exception, "Error building bytearray for header padding");
                goto out;
            }
            sig_hdr_padded = PyByteArray_Concat(sig_hdr, sig_hdr_pad);
            if (sig_hdr_padded == NULL) {
                PyErr_SetString(PyExc_Exception, "Error padding signature header");
                goto out;
            }

            // Replace sig_hdr with the sig_hdr_padded version
            Py_CLEAR(sig_hdr);
            sig_hdr = sig_hdr_padded;
            sig_hdr_padded = NULL;
        }

        return_value = PyByteArray_Concat(sig_hdr_magic, sig_hdr);
        if (return_value == NULL) {
            PyErr_SetString(PyExc_Exception, "Error building signature header");
            goto out;
        }

    } else if (insSig) {
        // Insert signature into RPM
        if (Fseek(rpm_fd, sigStart, SEEK_SET) < 0) {
            PyErr_Format(PyExc_Exception, "Error seeking RPM file to start of signature: %s", Fstrerror(rpm_fd));
            goto out;
        }
        if (rpmWriteSignature(rpm_fd, sigh)) {
            PyErr_Format(PyExc_Exception, "Error writing signature: %s", Fstrerror(rpm_fd));
            goto out;
        }

    } else {
        // Create new RPM
        rasprintf(&trpm, "%s.XXXXXX", rpm_path);
        rpm_ofd = rpmMkTemp(trpm);
        if (rpm_fd == NULL || Ferror(rpm_ofd)) {
            PyErr_Format(PyExc_Exception, "Error opening RPM output file: %s", Fstrerror(rpm_ofd));
            goto out;
        }

#ifdef RPM_411
        lead = rpmLeadFromHeader(h);
        if (rpmLeadWrite(rpm_ofd, lead)) {
#else
        if (rpmLeadWrite(rpm_ofd, h)) {
#endif
            PyErr_Format(PyExc_Exception, "Error writing lead: %s", Fstrerror(rpm_ofd));
            goto out;
        }
        if (rpmWriteSignature(rpm_ofd, sigh)) {
            PyErr_Format(PyExc_Exception, "Error writing signature header: %s", Fstrerror(rpm_ofd));
            goto out;
        }
        if (Fseek(rpm_fd, headerStart, SEEK_SET) < 0) {
            PyErr_Format(PyExc_Exception, "Error seeking RPM source: %s", Fstrerror(rpm_fd));
            goto out;
        }
        if (!copyFile(&rpm_fd, &rpm_ofd)) {
            // This function sets Python exceptions itself
            goto out;
        }

        struct stat st;
        if (stat(rpm_path, &st)) {
            PyErr_Format(PyExc_Exception, "Error getting stat on RPM path: %s", strerror(errno));
            goto out;
        }
        if (unlink(rpm_path)) {
            PyErr_Format(PyExc_Exception, "Error removing old RPM: %s", strerror(errno));
            goto out;
        }
        if (rename(trpm, rpm_path)) {
            PyErr_Format(PyExc_Exception, "Error moving new RPM into place: %s", strerror(errno));
            goto out;
        }
        if (chmod(rpm_path, st.st_mode)) {
            PyErr_Format(PyExc_Exception, "Error setting permissions on new file: %s", strerror(errno));
            goto out;
        }
    }

    success = true;

out:
    if (sigp != NULL) pgpDigParamsFree(sigp);
    if (rpm_fd) Fclose(rpm_fd);
    if (rpm_ofd) Fclose(rpm_ofd);

#ifdef RPM_411
    rpmLeadFree(lead);
#endif

    Py_CLEAR(sig_hdr_magic);
    Py_CLEAR(sig_hdr);
    Py_CLEAR(sig_hdr_pad);
    Py_CLEAR(sig_hdr_padded);
    headerFree(sigh);
    headerFree(h);
    free(trpm);
    free(msg);
#ifdef RPM_411
    if (sigtd != NULL && sigtd->data != NULL) free(sigtd->data);
#endif
    if (sigtd != NULL) rpmtdFree(sigtd);

    if (success) {
        if (return_value == NULL) {
            Py_RETURN_NONE;
        } else {
            return return_value;
        }
    } else {
        return NULL;
    }
}

static PyMethodDef InsertLibMethods[] = {
    {"insert_signatures", insert_signatures, METH_VARARGS, "Insert signatures into an RPM"},
};

#if PY_MAJOR_VERSION == 2
PyMODINIT_FUNC
initinsertlib(void)
{
    (void) Py_InitModule("insertlib", InsertLibMethods);
}

#elif PY_MAJOR_VERSION == 3
static struct PyModuleDef insertlib_module = {
    PyModuleDef_HEAD_INIT,
    "insertlib",
    NULL,
    -1,
    InsertLibMethods,
};

PyMODINIT_FUNC
PyInit_insertlib(void)
{
    return PyModule_Create(&insertlib_module);
}

#else
#error "Only Py2 and Py3 supported"
#endif
