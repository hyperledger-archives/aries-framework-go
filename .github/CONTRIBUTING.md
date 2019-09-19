# How to contribute

*We are still working on improving these guidelines.*

Thank you for taking the time to contribute to `hyperledger/aries-framework-go`!

There are several ways you can contribute:

* Submit a [proposal](#proposals)
* Submit a [bug report](#bug-report)
* Submit a [pull request](#pull-request)

## Proposals

You can submit new ideas or proposals for enhancements just like any other
GitHub issue.  Tag one of the
[maintainers](https://github.com/orgs/hyperledger/teams/aries-framework-go-committers)
in your proposal's description to get their attention.  Your proposal will be
pulled into one of the project's
[boards](https://github.com/hyperledger/aries-framework-go/projects) once the
proposal is deemed to be worth pursuing.  From there, further discovery may be
required before actual implementation work gets started.

## Bug Report

Did you find a bug? Be sure to set a clear and concise title. Do your best to
include a code sample that illustrates the test case. Use the
[template](ISSUE_TEMPLATE.md). Also make sure:

* **Required:** make sure your system satisfies all the pre-requisites listed
in the `README`
* **Required:** ensure the bug is not a duplicate already reported under
[Issues](https://github.com/hyperledger/aries-framework-go/issues)

## Pull Request

Use the [template](PULL_REQUEST_TEMPLATE.md) and also make sure:

* **Required:** The build must pass. In particular, the following build targets
must pass successfully:
  * `make checks`
  * `make unit-test`
  * `make bdd-test`
* **Required:** Adherence to the  [Developer Certificate of Origin
(DCO)](https://developercertificate.org/) version 1.1 (`git --signoff`).
* **Required:** *squash your commits*. Yes, we know - it's nice to be able to
rollback every single change you make while troubleshooting or when requested to
exclude a subset or your change. The problem is the project's history tends to
become polluted with useless commit messages such as "removed trailing spaces".
It also makes it harder to revert specific changes when they are spread out like
this. We care about preserving our project's commit history in a usable state,
and as such, we politely request that you deliver your changes in a single
commit.
* Number of lines changed should not exceed 500. We're reasonable people - if
your PR is just a *little* over the top then we might still merge it. Such cases
are exceptional and are handled on a case-by-case basis.
