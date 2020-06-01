package burp;

class Cookie {

    public String name;
    public String sameSite;
    public boolean issue = false;
    
    public Cookie(String setCookie) {
        String name;

        name = setCookie.substring(0, setCookie.indexOf("="));
        this.name = name;

        // Iterate on cookie flag delimiters
        for (String flag : setCookie.split(";")) {
            flag = flag.replaceAll("\\s+", "");
            flag = flag.toLowerCase();

            // only parse flags with `key=val' notation
            int equalDelimiter = flag.indexOf("=");
            if (equalDelimiter != -1) {
                String key_name = flag.substring(0, equalDelimiter); 
                String key_val = flag.substring(equalDelimiter + 1, flag.length()); 

                if (key_name.equals("samesite")) {
                    switch(key_val) {
                    case "lax":
                    case "strict":
                        break;
                    case "none":
                        this.sameSite = "none";
                        this.issue = true;
                    } 
                    return;
                }
            } 
        }

        this.sameSite = "missing";
        this.issue = true;
    }
}
