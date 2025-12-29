# SQLi LAB REPORT

In this report, the OWASP Juice Shop webapp is used to showcase the exploitation of two SQLi vulnerabilities.

## Tools

- OWASP Juice Shop
- BURP Suite Proxy

## Challenge #1. Authentication bypass

For this challenge, we try to find a way to log in as administrator on the web application.\
We navigate to the login page of the OWASP Juice Shop web application and we try logging in as admin using a test password.
By capturing the traffic using BURP, we notice that the request contains the following data: `{"email":"admin","password":"admin"}`.
We now try a basic injection query `{"email":"admin' OR '1'='1' --","password":"password"}`, which inserts an always valid condition
and comments out the rest of the query. This injection attempt works, and we log in as admin, solving the challenge.

![img.png](REPORT_FILES/scrsh1.png)

## Challenge #2. Data extraction

For this challenge, we try to exfiltrate Juice Shop's database schema.\
For data estraction, different methods can be used to probe the system depending on the level of information
we obtain back from the server.

## Takeaways

SQL injection is a solved problem nowadays. The simplest way to prevent it is to exclusively
use prepared statements, which are precompiled by the SQL engine and, as such, cannot be injected
with unwanted commands. For example, if I prepare a statement which has a SELECT and a parameter in the WHERE
condition, the SQL engine will compile it so that whatever is put inside the parameter must be compatible
with a condition.