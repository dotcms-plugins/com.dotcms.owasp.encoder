# Owasp Encoder Plugin

This plugin provides a Velocity viewtool that is intended to help prevent XSS based attacks.  It wraps the methods made available by the Owasp Encoder class that can be called in your velocity code to sanitize the output of your templates.

For more information on how to use, see the OWASP docs https://owasp.org/www-project-java-encoder/



Examples:

```
#set($url = "https://www.google.com/search?q=maven+repository&oq=maven&aqs=chrome.1.<script>alert('test');</script>.2855j0j1&sourceid=chrome&ie=UTF-8")

$owasp.validateUrl($url)

$owasp.forHtmlAttribute($url)

$owasp.urlHasXSS($url)

$owasp.forHtml("<script>window.location='/bad-url?doBadThings=true';</script>")

```
