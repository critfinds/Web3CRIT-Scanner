# Publishing Web3CRIT Scanner to npm

This guide explains how to publish the Web3CRIT Scanner package to the npm registry.

## Prerequisites

1. **npm Account**: You need an npm account. Create one at https://www.npmjs.com/signup

2. **Login to npm**:
   ```bash
   npm login
   ```
   Enter your username, password, and email when prompted.

3. **Verify Login**:
   ```bash
   npm whoami
   ```

## Pre-Publish Checklist

Before publishing, ensure:

- [ ] All tests pass
- [ ] Version number is updated in package.json
- [ ] README.md is up to date
- [ ] INSTALL.md has correct installation instructions
- [ ] All changes are committed to git
- [ ] Package builds correctly

## Testing the Package Locally

Test the package before publishing:

```bash
# Dry run - see what will be published
npm pack --dry-run

# Create actual tarball for testing
npm pack

# Install the tarball locally
npm install -g ./web3crit-scanner-4.0.0.tgz

# Test the installation
web3crit --version
web3crit scan test/contracts/secure/SecurePatterns.sol

# Clean up
rm web3crit-scanner-4.0.0.tgz
```

## Publishing Steps

### 1. Update Version (if needed)

Follow semantic versioning (semver):
- **Patch** (4.0.1): Bug fixes
- **Minor** (4.1.0): New features, backwards compatible
- **Major** (5.0.0): Breaking changes

```bash
# For patch release
npm version patch

# For minor release
npm version minor

# For major release
npm version major
```

### 2. Publish to npm

```bash
# Publish as public package
npm publish --access public

# For scoped packages (e.g., @username/web3crit-scanner)
npm publish --access public
```

### 3. Verify Publication

```bash
# Check on npm registry
npm view web3crit-scanner

# Test installation from npm
npm install -g web3crit-scanner

# Verify it works
web3crit --version
```

### 4. Tag the Release in Git

```bash
# Create git tag
git tag -a v4.0.0 -m "Release version 4.0.0"

# Push tags to remote
git push origin --tags
```

## Post-Publication

After publishing:

1. Update README.md installation instructions to use npm package
2. Create GitHub release with changelog
3. Announce the release

## Updating an Existing Package

To publish an update:

```bash
# 1. Make your changes and commit
git add .
git commit -m "fix: your changes"

# 2. Update version
npm version patch  # or minor/major

# 3. Publish
npm publish

# 4. Push changes and tags
git push origin main --tags
```

## Troubleshooting

### Package Name Already Taken

If "web3crit-scanner" is already taken:

1. Choose a new name in package.json:
   ```json
   {
     "name": "@yourusername/web3crit-scanner"
   }
   ```

2. Publish with your scope:
   ```bash
   npm publish --access public
   ```

### Permission Denied

Make sure you're logged in:
```bash
npm login
npm whoami
```

### Package Too Large

Check package size:
```bash
npm pack --dry-run
```

Ensure .npmignore excludes unnecessary files.

## Unpublishing (DANGER)

Only unpublish within 72 hours of publishing:

```bash
npm unpublish web3crit-scanner@4.0.0
```

WARNING: Unpublishing is permanent and discouraged. Use `npm deprecate` instead:

```bash
npm deprecate web3crit-scanner@4.0.0 "Please upgrade to 4.0.1"
```

## Security

For security updates:

1. Fix the vulnerability
2. Publish new version
3. Report to GitHub Security Advisories
4. Notify users via npm advisory

## References

- npm Publish Documentation: https://docs.npmjs.com/cli/v8/commands/npm-publish
- Semantic Versioning: https://semver.org/
- npm Package Naming: https://docs.npmjs.com/package-name-guidelines
