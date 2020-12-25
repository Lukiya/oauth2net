def exists(hosts, host: str) -> bool:
    return host in hosts
try:
    f = open("C:/Windows/System32/drivers/etc/hosts", "r+")
    hosts = f.read()
    print(exists(hosts, "i.test.com"))
    print(exists(hosts, "w.test.com"))
    print(exists(hosts, "p.test.com"))
except IOError as ex:
    print(ex)
finally:
    f.close()