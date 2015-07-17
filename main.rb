require "vault"
require "pry"

root = Vault::Client.new(address: "http://127.0.0.1:8200", token: "")
init = root.sys.init
init.keys.first(3).each { |key| root.sys.unseal(key) }

root = Vault::Client.new(
  address: "http://127.0.0.1:8200",
  token: init.root_token
)

username = "zeeraw"
password = "secret1234"
policy = <<-EOF
path "sys/" {
  policy = "deny"
}
path "secret/" {
  policy = "write"
}
path "privy/" {
  policy = "write"
}
EOF

begin
  root.sys.enable_audit("file-audit", "file", "", path: "/Users/zeeraw/Projects/dxw/vault-test/vault.log")
rescue Vault::HTTPError
end

begin
  root.sys.put_policy("regular", policy)
rescue Vault::HTTPError
end

begin
  root.sys.enable_auth("userpass", "userpass")
rescue Vault::HTTPError
end

begin
  root.sys.mount("privy", "generic", "privy password storage")
rescue Vault::HTTPError
end

begin
  root.logical.write("auth/userpass/users/#{ username }", password: password, policies: "regular")
rescue Vault::HTTPError
end

user = Vault::Client.new(
  address: "http://127.0.0.1:8200",
  token: root.post("v1/auth/userpass/login/#{ username }", JSON.fast_generate(password: password))[:auth][:client_token]
)

binding.pry