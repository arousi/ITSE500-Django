# Commit Message Structure

## Guidelines

- Commit titles must follow the 'Conventional Commits Format' + the modifications for agile sprints if it was an agile project
- Commit messages should be descriptive and concise.
- Use the following format for commit messages:

### Format

"""
`SprintN`[`Framework`](Type) Description of the change
"""

or

"""
`SprintN`[`Document`](Type) Description of the change
"""
for changes to documents of the project, take the 'Type' from the ###Types below.

### Examples

- `Sprint5`[`Django`](feat) Add new serializer for user registration
- `Sprint5`[`Flutter`](fix) Fix widget alignment issue in login screen
- `Sprint5`[`React`](refactor) Refactor state management in dashboard component

### Types

- **feat**: A new feature.
- **bugfix**: A bug fix.
- **refactor**: Code changes that neither fix a bug nor add a feature.
- **test**: Adding or updating tests.
- **chores**: Maintenance tasks.
- **docs**: added or modified documents
- **init**: initiation of a directory or a specific part of the repo

### Notes

- Always include the sprint number and framework in the commit message.
- Use the type to categorize the change.
- Ensure the description is clear and provides context for the change.
