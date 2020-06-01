# burp-samesite-reporter
Burp extension that passively reports various SameSite flags.

This extension reports cases where the `SameSite` cookie flag is explicitly set to `None`, and when it is missing. Handy for developers who want to write secure code, and testers who like me often forget to check the `SameSite` value of important cookies.

### SameSite=None
![Samesite None Issue](img/none_samesite_issue.png)
![Samesite None Response](img/none_samesite_response.png)

### SameSite Missing
![Samesite Missing Issue](img/missing_samesite_issue.png)
![Samesite Missing Response](img/missing_samesite_response.png)
