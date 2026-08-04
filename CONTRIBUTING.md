# Contributing Guidelines

Thank you for contributing to the Distributed Vulnerability Scan Orchestration Engine. 

## Development Workflow
1. Branch off `main` for all features/fixes (e.g., `feature/add-nuclei-adapter`).
2. Do not commit `.env` files or secrets.
3. Keep business logic in the Control Plane (API/Workers) and execution logic in the Scanner Plane (Agents).
4. Run `make lint` and `make format` before committing.
5. All tests must pass (`make test`).

## Pull Request Process
- Ensure PR descriptions clearly describe the problem and the proposed solution.
- Request review from a CODEOWNER.
- Squash commits before merging.
