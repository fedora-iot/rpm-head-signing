# rpm-head-signing
This is a small Python module (with C helper) to extract a RPM header and file digests and reinsert the signature and signed file digests.
This is used for when you want to retrieve the parts to sign if you have a remote signing server without having to transmit the entire RPM over to the server.

Note that this only supports RPM 4.x signatures (for RPM 3, this is not useful anyway, since they sign the entire object instead of just the header).
