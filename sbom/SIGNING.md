# SBOM Signing Instructions

**Version:** HDDS 1.0.8
**Signer:** HDDS Team

## Artifacts to Sign

- `sbom/hdds-1.0.8.cdx.json` (CycloneDX JSON)
- `sbom/hdds-1.0.8.cdx.xml` (CycloneDX XML)

## Step 1: Verify Checksums

```bash
cd sbom/
sha256sum -c SHA256SUMS
```

Both files must report `OK` before proceeding.

## Step 2: GPG Signing

### Sign the JSON SBOM

```bash
gpg --armor --detach-sign --output hdds-1.0.8.cdx.json.asc hdds-1.0.8.cdx.json
```

### Sign the XML SBOM

```bash
gpg --armor --detach-sign --output hdds-1.0.8.cdx.xml.asc hdds-1.0.8.cdx.xml
```

### Verify GPG Signatures

```bash
gpg --verify hdds-1.0.8.cdx.json.asc hdds-1.0.8.cdx.json
gpg --verify hdds-1.0.8.cdx.xml.asc hdds-1.0.8.cdx.xml
```

Both must print `Good signature from` with the expected key identity.

## Step 3: Cosign Signing (Sigstore keyless)

### Sign with cosign (OIDC identity)

```bash
cosign sign-blob --output-signature hdds-1.0.8.cdx.json.sig \
                 --output-certificate hdds-1.0.8.cdx.json.cert \
                 hdds-1.0.8.cdx.json

cosign sign-blob --output-signature hdds-1.0.8.cdx.xml.sig \
                 --output-certificate hdds-1.0.8.cdx.xml.cert \
                 hdds-1.0.8.cdx.xml
```

This opens a browser for OIDC authentication. Sign in with the naskel.com identity.

### Expected OIDC Identity

- **Issuer:** `https://accounts.google.com` (or configured OIDC provider)
- **Subject:** HDDS team email associated with the naskel.com GPG key

### Verify Cosign Signatures

```bash
cosign verify-blob --signature hdds-1.0.8.cdx.json.sig \
                   --certificate hdds-1.0.8.cdx.json.cert \
                   --certificate-identity-regexp ".*@naskel\.com" \
                   --certificate-oidc-issuer "https://accounts.google.com" \
                   hdds-1.0.8.cdx.json

cosign verify-blob --signature hdds-1.0.8.cdx.xml.sig \
                   --certificate hdds-1.0.8.cdx.xml.cert \
                   --certificate-identity-regexp ".*@naskel\.com" \
                   --certificate-oidc-issuer "https://accounts.google.com" \
                   hdds-1.0.8.cdx.xml
```

Both must print `Verified OK`.

## Step 4: Regenerate SHA256SUMS

After signing, regenerate the checksums to include all artifacts:

```bash
cd sbom/
sha256sum hdds-1.0.8.cdx.json hdds-1.0.8.cdx.xml \
          hdds-1.0.8.cdx.json.asc hdds-1.0.8.cdx.xml.asc \
          hdds-1.0.8.cdx.json.sig hdds-1.0.8.cdx.xml.sig \
          hdds-1.0.8.cdx.json.cert hdds-1.0.8.cdx.xml.cert \
          > SHA256SUMS
```

### Verify final checksums

```bash
sha256sum -c SHA256SUMS
```

All 8 files must report `OK`.

## Checklist

- [ ] `sha256sum -c SHA256SUMS` passes (pre-signing)
- [ ] GPG detached signatures created (`.asc`)
- [ ] GPG signatures verified
- [ ] Cosign keyless signatures created (`.sig` + `.cert`)
- [ ] Cosign signatures verified with identity and issuer
- [ ] SHA256SUMS regenerated with all 8 artifacts
- [ ] Final `sha256sum -c SHA256SUMS` passes
