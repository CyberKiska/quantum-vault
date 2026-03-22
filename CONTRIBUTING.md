# Contributing

This repository uses a branch-and-pull-request workflow.

## Internal contributors

If you have write access to this repository:

1. Create a feature branch from `main`.
2. Make your changes on that branch.
3. Run the relevant local checks before opening a pull request:

```bash
npm run selftest
npm run build
```

4. Open a pull request targeting `main`.
5. Wait for GitHub Actions CI to pass.
6. Address review feedback and update the pull request as needed.
7. After approval and passing checks, the pull request can be merged into `main`.

## External contributors

If you do not have write access to this repository:

1. Fork the repository.
2. Create a feature branch in your fork.
3. Make your changes on that branch.
4. Run the relevant local checks before opening a pull request:

```bash
npm run selftest
npm run build
```

5. Open a pull request from your fork to this repository's `main` branch.
6. Address review feedback and update the pull request as needed.

## Important rules

- Do not push directly to `main`.
- Keep pull requests focused and reviewable.
- If you change security-sensitive behavior, cryptographic logic, workflow behavior, or trust/policy semantics, update the relevant documentation in `docs/`.

## Deployment

- GitHub Pages is published from `main` by GitHub Actions after the required workflow succeeds.
- Contributors do not deploy manually as part of the normal contribution process.
