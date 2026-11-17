# SBOM Signing Instructions

**Version:** `<version>` (the HDDS release being signed)
**Signer:** HDDS Team

## Artifacts to Sign

- `sbom/hdds-<version>.cdx.json` (CycloneDX JSON)
- `sbom/hdds-<version>.cdx.xml` (CycloneDX XML)

## Step 1: Verify Checksums

```bash
cd sbom/
sha256sum -c SHA256SUMS
```

Both files must report `OK` before proceeding.

## Step 2: GPG Signing

### Sign the JSON SBOM

```bash
gpg --armor --detach-sign --output hdds-<version>.cdx.json.asc hdds-<version>.cdx.json
```

### Sign the XML SBOM

```bash
gpg --armor --detach-sign --output hdds-<version>.cdx.xml.asc hdds-<version>.cdx.xml
```

### Verify GPG Signatures

```bash
gpg --verify hdds-<version>.cdx.json.asc hdds-<version>.cdx.json
gpg --verify hdds-<version>.cdx.xml.asc hdds-<version>.cdx.xml
```

Both must print `Good signature from` with the expected key identity.

## Step 3: Cosign Signing (Sigstore keyless)

### Sign with cosign (OIDC identity)

```bash
cosign sign-blob --output-signature hdds-<version>.cdx.json.sig \
                 --output-certificate hdds-<version>.cdx.json.cert \
                 hdds-<version>.cdx.json

cosign sign-blob --output-signature hdds-<version>.cdx.xml.sig \
                 --output-certificate hdds-<version>.cdx.xml.cert \
                 hdds-<version>.cdx.xml
```

This opens a browser for OIDC authentication. Sign in with the naskel.com identity.

### Expected OIDC Identity

- **Issuer:** `https://accounts.google.com` (or configured OIDC provider)
- **Subject:** HDDS team email associated with the naskel.com GPG key

### Verify Cosign Signatures

```bash
cosign verify-blob --signature hdds-<version>.cdx.json.sig \
                   --certificate hdds-<version>.cdx.json.cert \
                   --certificate-identity-regexp ".*@naskel\.com" \
                   --certificate-oidc-issuer "https://accounts.google.com" \
                   hdds-<version>.cdx.json

cosign verify-blob --signature hdds-<version>.cdx.xml.sig \
                   --certificate hdds-<version>.cdx.xml.cert \
                   --certificate-identity-regexp ".*@naskel\.com" \
                   --certificate-oidc-issuer "https://accounts.google.com" \
                   hdds-<version>.cdx.xml
```

Both must print `Verified OK`.

## Step 4: Regenerate SHA256SUMS

After signing, regenerate the checksums to include all artifacts:

```bash
cd sbom/
sha256sum hdds-<version>.cdx.json hdds-<version>.cdx.xml \
          hdds-<version>.cdx.json.asc hdds-<version>.cdx.xml.asc \
          hdds-<version>.cdx.json.sig hdds-<version>.cdx.xml.sig \
          hdds-<version>.cdx.json.cert hdds-<version>.cdx.xml.cert \
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
