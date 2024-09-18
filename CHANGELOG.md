# respec-vc ChangeLog

## x.x.x - yyyy-mm-dd

### Added
-

### Changed
-

### Fixed
-

## 3.x.x - 2024-mm-dd

### Fixed
- Moved `sd-jwt` tab to end of tab list to fix `cose` rendering.

## 3.3.3 - 2024-08-07

### Added
- Support rendering Enveloped Verifiable Presentations.

## 3.3.2 - 2024-07-05

### Fixed
- Removed the onclick event for loading tab contents to allow better Respec
  exporting.
- Create truly unique IDs for example tab content.

## 3.3.0 - 2024-07-02

### Added
- Attached payloads and presentations for COSE.

## 3.2.0 - 2024-06-18

### Fixed
- Fixed `data-vc-tabs` to work with multiple space-delimited values.
- Fixed media types to use `application/vc` and `application/vp`.

## 3.1.0 - 2024-06-02

### Added
- Option to generate URL digests for openssl, digestSRI, and digestMultibase.
- `ecdsa-sd-2023` integration and tab option.
- `ecdsa-rdfc-2019` integration and tab option.
- `bbs-2023` integration and tab option.

### Changed
- Refactored instantiation of proofs to include key material.
- Reworked tab titles to reduce space requirement.
- Tab clicks now initiate credential example creation.

### Fixed
- Corrected how `purposes` was being set.
- Added missing `data-vc-tabs` documentation to README.
- Corrected `verificationMethod` values.
- Used `kid` in VC-JWT example.

## 3.0.0 - 2024-05-07

### Added
- Added `eddsa-rdfc-2022` integration and tab option.
- Added `data-vc-tabs` feature for selecting specific tabs to display.
- Added VC v2.0 support via library upgrades.

### Changed
- Made example match one from the VCDM v2.0 specification.
- Added W3C copyright and code of conduct information.
- Repository moved to the W3C.

## 2.0.1 - 2023-06-11

### Changed
- Simplified examples context to just a `@vocab` definition (to match upstream).
- Minified `dist/main.js` file.

### Removed
- Removed VC v1.1 example from index.html.

## 2.0.0 - 2023-01-15

### Changed
- Rerelease of v1.0.1, but with a major version bump and improved example code.

## 1.0.1 - 2022-01-15

### Added
- Add comment to JWT output noting duplication of fields.

## 1.0.0 - 2021-11-21

### Added
- Added usage instructions to README.md.
- Added JWT header and payload to JWT output.

### Changed
- Programmatically inject tab styles and script.
- Changed from buttons to tabs.

### Fixed
- Fix race condition when setting example styles.
- Fixed JWT payload transformations from credential data.

## 0.0.2 - 2021-11-10

### Fixed
- Fixed to work with static ReSpec files.

## 0.0.1 - 2021-11-10

### Added
- Added LDI and JWT examples.
- Added example test HTML page.
- Created initial working implementation.
