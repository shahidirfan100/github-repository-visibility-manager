# GitHub Repository Visibility Manager

A small Windows desktop application for reviewing repositories and changing their visibility between **public** and **private** through GitHub's REST API.

## Features

- Load repositories accessible to the authenticated GitHub account.
- Search and filter by name, owner, description, visibility, admin access, fork, and archived status.
- Select individual repositories or all repositories currently visible through the filters.
- Change selected repositories to public or private.
- Optionally save a visibility snapshot before a change and restore it later.
- Check repository administration permission before a bulk change, report progress, and stop a running batch.
- Cache repository metadata locally for up to 30 minutes; **Refresh from GitHub** bypasses the cache.

## Requirements

- Windows 10 or Windows 11
- Python 3.10 or newer, including Tkinter
- No third-party Python packages

## Run

1. Download `github_repo_visibility_manager.pyw` and place it in a writable folder.
2. Double-click the `.pyw` file, or run it with `pythonw.exe`.
3. Enter a GitHub personal access token and select **Connect & Load**.
4. Select the repositories, review the current visibility, and choose the public or private action.

For a fine-grained personal access token, use the correct resource owner, restrict repository access to the repositories you need, and grant **Administration: Read and write**. The app cannot change visibility for repositories where the token lacks administration write permission.

## Token and local data security

The token is sent in an HTTPS `Authorization` header to `https://api.github.com` for GitHub API requests. The application source contains no embedded token and makes no analytics or telemetry requests.

When **Save securely with Windows DPAPI** is enabled, the app stores the token encrypted for the current Windows user under `%APPDATA%\GitHubRepoVisibilityManager`. The token is not stored as plain text. Turning off secure saving removes the saved encrypted token; the token remains in memory while the app is running.

The optional local repository cache stores repository metadata and a short token fingerprint to prevent reuse across tokens. It does not store the token. Do not commit runtime cache files: this repository ignores `cache/*.json` and other generated cache data. The cache can contain private repository names, descriptions, and status information.

## Before making repositories public

Review the repositories' files, full Git history, configuration, Actions logs, issues, and releases for credentials or private information. Making a repository private again does not reverse information already copied while it was public. This application changes repository visibility; it does not audit the contents of the repositories being changed.

## License

No license is included. Without a license, standard copyright applies and others do not automatically receive permission to reuse or distribute this code. Add a license if you want to grant those permissions.

