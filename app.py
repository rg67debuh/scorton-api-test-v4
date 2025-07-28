import uvicorn
from fastapi import FastAPI, HTTPException, Request

import schemas
from db import Base, engine
from auth_route import auth_router, verify_token
from utils import (
    dns_enum,
    url_analyze,
    whois_scan,
    headers_check,
    port_scan,
    dmarc_scan,
    ssl_scan,
    snallygaster_scan,
    subdomain_scan,
    methods_scan,
    dir_scan,
    reverse_dns,
    xss_scan,
    cookie_scan,
)

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(auth_router, prefix="/auth")

@app.get("/", status_code=200)
def root():
    return {"message": "OK"}

@app.post("/dns-enum", status_code=200)
def post_dns_enum(req: schemas.DnsEnumRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse = dns_enum.main(target, api=True)
    return reponse


@app.post("/headers-check", status_code=200)
def post_headers_check(req: schemas.HeadersCheckRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  headers_check.main(target, api=True)
    return reponse


@app.post("/url-analyse", status_code=200)
def post_url_analyse(req: schemas.UrlAnalyseRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  url_analyze.main(target, api=True)
    return reponse


@app.post("/whois-scan", status_code=200)
def post_whois_scan(req: schemas.WhoisScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  whois_scan.main(target, api=True)
    return reponse

@app.post("/port-scan", status_code=200)
def post_port_scan(req: schemas.PortScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  port_scan.main(target, api=True)
    return reponse

@app.post("/dmarc-scan", status_code=200)
def post_dmarc_scan(req: schemas.DmarcScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  dmarc_scan.main(target, api=True)
    return reponse


@app.post("/ssl-scan", status_code=200)
def post_ssl_scan(req: schemas.SslScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  ssl_scan.main(target, api=True)
    return reponse


@app.post("/snallygaster-scan", status_code=200)
def post_snallygaster_scan(req: schemas.SnallygasterScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  snallygaster_scan.main(target, api=True)
    return reponse


@app.post("/subdomain-scan", status_code=200)
def post_subdomain_scan(req: schemas.SubdomainScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  subdomain_scan.main(target, api=True)
    return reponse


@app.post("/methods-scan", status_code=200)
def post_methods_scan(req: schemas.MethodsScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  methods_scan.main(target, api=True)
    return reponse


@app.post("/dir-scan", status_code=200)
def post_dir_scan(req: schemas.DirScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  dir_scan.main(target, api=True)
    return reponse


@app.post("/reverse-dns", status_code=200)
def post_reverse_dns(req: schemas.ReverseDnsRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  reverse_dns.main(target, api=True)
    return reponse


@app.post("/xss-scan", status_code=200)
def post_xss_scan(req: schemas.XssScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  xss_scan.main(target, api=True)
    return reponse


@app.post("/cookie-scan", status_code=200)
def post_cookie_scan(req: schemas.CookieScanRequest, request: Request):

    auth_header = request.headers.get("AUTH")
    if not auth_header:
        raise HTTPException(status_code=400, detail="Bad Request: Missing or invalid token.")
    verify_token(token=auth_header)

    target = req.target
    if not target:
        raise HTTPException(status_code=400, detail="Bad Request: Missing argument.")

    reponse =  cookie_scan.main(target, api=True)
    return reponse




if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=2711, reload=True, log_level="info")
