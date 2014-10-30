#Design Goals


Nogotofail was designed to be an automated, powerful, flexible and scalable tool
for testing for network security issues on any device whose network traffic
could be made to go through it. We built nogotofail with three use cases in mind.

1. Finding bugs and vulnerabilities.
2. Verifying fixes and watching for regressions.
3. Understanding what applications and devices are generating what traffic.

For these use cases we wanted to build a tool that was flexible enough to work
anywhere on path and be able to test any device that makes network traffic. We
decided to focus on testing real devices as opposed to emulators, because it is
real devices that matter. We wanted to avoid any modifications to the device
under test.

It is also real behavior that matters. Therefore we wanted to design the tool
such that it does not get in the way of using devices as normal. Tests
that are destructive are by default run only when necessary and with low
probability.

##The building blocks of nogotofail

Nogotofail is centered around a on path man in the middle tool written in python
with an optional client application to provide additional attribution and
configuration support.

###Man in The Middle

The core of nogotofail is the on path network MiTM named nogotofail.mitm that
intercepts TCP traffic. It is designed to primarily run on path and centers
around a set of handlers for each connection which are responsible for actively
modifying traffic to test for vulnerabilities or passively look for issues.
nogotofail is completely port agnostic and instead detects vulnerable traffic
using DPI instead of based on port numbers. Additionally, because it uses DPI,
it is capable of testing TLS/SSL traffic in protocols that use STARTTLS.

####Why attack probabilistically?

Nogotofail does not destructively attack all TLS/SSL connections it sees because
such attacks lead to non-vulnerable clients aborting attacked connections. If
you did attack all connections you might never see vulnerable connections which
had a dependency on a non-vulnerable connection succeeding. For example, say you
have to log in to a service over HTTPS before you can do some
action which results in vulnerable traffic. If the login never
succeeds you will never get to the vulnerable traffic.

Also, typical retry logic masks transient connection errors. Thus, using a low
attack probability leaves devices in a useable state. This lets you leave
devices on nogotofail for long periods of time and still use them as normal,
giving you much better test coverage. At 10% probability connection retries mask
most of the issues caused by attacking TLS/SSL connections and most
devices we’ve seen tend to work as usual.

Of course, if you want to test a specific connection aggressively you can push
the probability up to 100%.

####Protocol sensing

Protocol sensing for a TLS/SSL testing tool is critical because only attacking
traffic on port 443 has two flaws. First, it misses TLS/SSL traffic on
non-standard ports, and second, it fails to test protocols that use STARTTLS.

###Client *(optional)*

####Why have a client?

When testing on real devices it can be very difficult to determine what component or app made a
vulnerable connection. Even seeing the contents and the destination isn’t always
enough to help figure out what made the connection. Connections made by an
application in the background for example can be nearly impossible to attribute
if it is connecting to a common endpoint. It is much better to be able to simply
ask the device who made the connection. This is achieved by having the optional nogotofail client
run on the device and communicate with the MiTM.

Also, we wanted to support multiple devices on the same infrastructure. This
quickly leads to the situation where one user wants a certain set of attacks run
at a certain rate and another user has a completely different need. Letting the
devices tell the MiTM how to attack them resolves this issue and adds flexibility.

Finally, the client receives notifications of vulnerabilities from the MiTM. This means you don’t have to be looking at the logs to see that there
were issues, and it helps you understand exactly what action triggered the
vulnerability.

####What the client does

The client exists to provide additional details about connections, allow the
client to configure attack settings, and to be notified when vulnerabilities are
detected. It doesn’t do any attacks and is only there to improve the quality of
testing.
