A Go library for interacting with ADC hubs and clients. The library has yet to form a coherent API, but the following utilities work reasonably well:

===adcget===
Fetches files from a hub by filename or Tiger Tree Hash with multi-sourced download. Supports http and https GET as well for backwards compatibility with utilities like wget. Can be used as the `$FETCHCOMMAND` in the Gentoo Portage package manager.


`go get code.google.com/p/go-adc/adcget`

> Usage: adcget [OPTIONS] URL
> Options:
>   -compress=false: EXPERIMENTAL: compress data transfer
>   -output="": output download to given file
>   -timeout=8s: ADC search timeout
>   -tth="LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ": search for a given Tiger tree hash


===adc_ping===
A Munin plugin to ping hubs and graph statistics.

`go get code.google.com/p/go-adc/adc_ping`

===adc-redirect===
A hub redirector with TLS support.

`go get code.google.com/p/go-adc/adc-redirect`

> Usage of adc-redirect:
>   -cert="": TLS certificate file
>   -key="": TLS key file
>   -log=false: log clients to Stdout
>   -message="": file containing a message to send to clients
>   -port=1511: port to listen for incoming connections on
>   -target="": hub to redirect clients to

> A message should contain the message you want displayed to clients.
> The redirector will make substitutions for the following tokens:
> 	 %t - the redirect taget
> 	 %n - Nickname of the user
> 	 %a - IP address of the user
> 	 %% - Becomes '%'
> A line starting with '!' followed by a number and a unit suffix will
> instruct the redirector to wait before continuing. Valid time units are
> 'ns', 'us' (or 'µs'), 'ms', 's', 'm', 'h'.

===adc-magnetize===
Hashes files and prints magnet links suitable for ADC.

> Usage of adc-magnetize:
>  -xs="": eXact Source link to a file (adc://example.com:1511)
>
> Example:
> $ adc-magnetize "Rite Near the Beach Boiii - Earth Mofo.ogg" 
>> magnet:?dn=Rite+Near+the+Beach+Boiii+-+Earth+Mofo.ogg&xl=2194545&xt=urn:tree:tiger:UMJ3QQSBLQ2LTNNNCP2FESQLJL5O4KQXGOD2UEQ
