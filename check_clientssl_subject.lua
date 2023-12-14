-- Set (partial) subjectname to check for in client cert
subjectname="CN=XXXXXX"

when CLIENTSSL_HANDSHAKE{
    -- Set Dictionary to request cert
    t={}
    t["direction"]="remote";
    t["operation"]="index";
    t["idx"]=0;
    t["type"]="info";

    -- Set cert variable to the client cert
    cert=SSL:cert(t)
    if cert["subject_name"]:starts_with(subjectname) then
        log("Client Certificate Matched: %s\n", cert["subject_name"])
    else
        log("No Matching Client Certificate Was Found: %s\n" , cert["subject_name"])
    end
}