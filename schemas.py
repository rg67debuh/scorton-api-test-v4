from pydantic import BaseModel, EmailStr

class SignUpRequest(BaseModel):
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Tools

class DnsEnumRequest(BaseModel):
    target: str

class HeadersCheckRequest(BaseModel):
    target: str

class UrlAnalyseRequest(BaseModel):
    target: str

class WhoisScanRequest(BaseModel):
    target: str
class PortScanRequest(BaseModel):
    target: str

class DmarcScanRequest(BaseModel):
    target: str

class SslScanRequest(BaseModel):
    target: str

class SnallygasterScanRequest(BaseModel):
    target: str

class SubdomainScanRequest(BaseModel):
    target: str

class MethodsScanRequest(BaseModel):
    target: str

class DirScanRequest(BaseModel):
    target: str

class ReverseDnsRequest(BaseModel):
    target: str

class XssScanRequest(BaseModel):
    target: str

class CookieScanRequest(BaseModel):
    target: str

