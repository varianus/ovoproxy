# ovoproxy

Simple Linux http/https proxy server.

It's written in Free Pascal/Lazarus and it aim to be simple and ligthweigtht.

## Some features
 - Ip filtering of clients trying to connect with allow and deny rules
 - Support Basic authentication for proxy access
 - Configurable port and bindings
 - tunable number of max connections, working threads, etc.

# Installing

**TBD**

# Build

To build ovoproxy you need a working install of the [Lazarus IDE](https://www.lazarus-ide.org/).
You also need [Indy networking library](https://www.indyproject.org/) for Lazarus. The simplest way to install it is using the lazarus [Online Package Manager](https://wiki.freepascal.org/Online_Package_Manager)

Open the ovoproxy.lpi project file inside the IDE, open menu "**Run**" and then "**Build**" or press **SHIFT+F9**.

You can also build from the command line using this command:
```
lazbuild -bm=Release ovoproxy.lpi
```

The executable **ovoproxy** will be created in the **bin** folder

# Alternative proxy software
A lots... The one I was using before ovoproxy is [TinyProxy](https://tinyproxy.github.io/), very good in my opinion.
