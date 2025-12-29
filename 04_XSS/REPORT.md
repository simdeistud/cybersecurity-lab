# XSS LAB REPORT

In this report, the OWASP Juice Shop webapp is used to showcase the exploitation of two XSS vulnerabilities.

## Tools

- OWASP Juice Shop
- BURP Suite Proxy
- 
## Challenge #1. DOM XSS attack

For this challenge, we will try to look for an input field where its content appears in the HTML when its form is submitted.
By examining at the main store page we notice a search bar on the top right. By pasting the payload HTML `<iframe src="javascript:alert(`xss`)">`
and performing the search, we successfully complete the challenge.

![scrsh1.png](REPORT_FILES/scrsh1.png)

## Challenge #2. Reflected XSS attack

For this challenge, we will try to look for a url parameter where its value appears in the page it is leading to.
We begin by creating an account under the email `test@test.test`, with password `Test123!`, and security answer `test`.
We then try to go through the procedure of purchasing one of the items. Once the purchase has been completed, a page
on which to track our order will be created, in my case: http://localhost:3000/#/track-result?id=dd46-194e9628d58cc016.
As we can see, this tracking page can be accessed with a certain URL parameter, which is also displayed on the page itself.

![img.png](REPORT_FILES/scrsh2.png)

By substituting into the URL our HTML payload, we solve the challenge.

![img.png](REPORT_FILES/scrsh3.png)

#### TODO: OBSERVATIONS
## Observations