# Contributing to aws-security-mcp

## Development Setup

```bash
git clone https://github.com/openclaw-ai/aws-security-mcp.git
cd aws-security-mcp
npm install
cd dashboard && npm install && cd ..
```

### Scripts

| Command | Description |
|---------|-------------|
| `npm run lint` | Type-check with `tsc --noEmit` |
| `npm test` | Run tests with Vitest |
| `npm run build` | Build MCP server with tsup |
| `npm run build:dashboard` | Build React dashboard |
| `npm run build:all` | Build server + dashboard |

## Adding a New Scanner

1. **Create the scanner file** in `src/scanners/<name>.ts`:

```typescript
import { Scanner, ScanContext, ScanResult } from './base.js';

export class MyScanner implements Scanner {
  readonly moduleName = 'my_service';

  async scan(ctx: ScanContext): Promise<ScanResult> {
    // Use only read-only AWS API calls (Describe/Get/List)
    // Handle both 'aws' and 'aws-cn' partitions via ctx.partition
    // Return findings with risk scores (0-10)
  }
}
```

2. **Register the scanner** in `src/index.ts`:

```typescript
import { MyScanner } from './scanners/my-scanner.js';

const allScanners: Scanner[] = [
  // ... existing scanners
  new MyScanner(),
];
```

This automatically creates:
- An MCP tool `scan_<moduleName>` for individual scanning
- Integration with `scan_all` for full scans
- Report generation and dashboard support

3. **Add tests** in `tests/` covering your scanner's findings and edge cases.

4. **Handle China regions** -- check `ctx.partition` for `aws-cn` and adjust ARN formats and service availability accordingly.

### Scanner Requirements

- **Read-only only**: Never use mutating API calls (Create/Update/Delete/Put)
- **Risk scores**: 0-10 scale mapping to CRITICAL (8-10), HIGH (6-7), MEDIUM (3-5), LOW (0-2)
- **Error handling**: Return `status: "error"` with a message, never throw unhandled exceptions
- **Partition awareness**: Support both `aws` and `aws-cn` partitions

## Running Tests

```bash
npm test           # Run all 21+ tests
npm run lint       # Type-check
```

All tests must pass before submitting a PR.

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes following the scanner requirements above
3. Ensure all checks pass: `npm run lint && npm test && npm run build:all`
4. Fill out the PR template completely
5. CI runs automatically on all PRs (lint, test, build across Node 18/20/22)

## Release Process

Releases are automated via GitHub Actions:

1. Update version in `package.json`
2. Create and push a tag: `git tag v0.2.0 && git push --tags`
3. The `publish.yml` workflow runs lint, test, build, and publishes to npm

The `NPM_TOKEN` secret must be configured in the repository settings.
