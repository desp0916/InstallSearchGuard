# Install Search Guard for Elasticsearch 2.3.1

[Search Guard](http://floragunn.com/searchguard/) 是 [flora gunn](http://floragunn.com/) 出的一套 Elasticsearch plugin，其用途類似於 Elastic 的 [Shield](https://www.elastic.co/products/shield)。但是因為 Shield 是 closed source 的、又不能單獨購買（必須同時購買其他產品與支援，詳情請參考 Elastic 的「[Subscriptions](https://www.elastic.co/subscriptions)」網頁），所以 Search Guard 就成為一些 Elasticsearch 用戶的第二選擇。不過 Search Guard 的設定過程滿繁瑣的，所以本文就是在說明 Search Guard Free 版的安裝細節。

我使用的軟體版本如下：

  - OS: CentOS 7.2.1511(Core)
  - Java: 1.7.0_79
  - Elasticsearch: 2.3.1 （我是[透過 yum 安裝的](https://www.elastic.co/guide/en/elasticsearch/reference/current/setup-repositories.html)）
  - search-guard-ssl: 2.3.1.8.1
  - search-guard-2: 2.3.1.0-beta1

另外，我只有在 VirtualBox 裡的一個 Elasticsearch node 上測試過而已，尚未於正式環境上的 Cluster 實際驗證過 。

## 1. 安裝一些 rpm 與兩個 plugins

建議先閱讀一下 [search-guard-ssl](https://github.com/floragunncom/search-guard-ssl) 的一篇 wiki —— [Open SSL setup](https://github.com/floragunncom/search-guard-ssl/wiki/Open-SSL-setup)。再依序執行以下指令：

```bash
# 安裝 openssl、openssl-devel、apr 這三個 rpms（如果你不想使用 Open SSL，可以不裝 apr）
yum install openssl openssl-devel apr
# 安裝 Apache Tomcat Native Library（如果你不想使用 Open SSL，此步驟可省略）
cd /usr/share/elasticsearch/plugins/search-guard-ssl && wget  "http://repo1.maven.org/maven2/io/netty/netty-tcnative/1.1.33.Fork13/netty-tcnative-1.1.33.Fork13-osx-x86_64.jar"
# 安裝 search-guard-ssl plugin，如果出現「WARNING: plugin requires additional permissions」的警告訊息，可以忽略不用理會
/usr/share/elasticsearch/bin/plugin install com.floragunn/search-guard-ssl/2.3.1.8.1
# 安裝 search-guard-2 plugin
/usr/share/elasticsearch/bin/plugin install com.floragunn/search-guard-2/2.3.1.0-beta1
# 設定 keytool 的 alternatives
alternatives --install /usr/bin/keytool keytool /usr/java/default/jre/bin/keytool 200000
```

安裝完兩個 plugin 以後，在你的 `/usr/share/elasticsearch/plugins/` 目錄下應該會出現「`search-guard-2`」和「`search-guard-ssl`」兩個目錄。

執行以下指令，打開 search-guard-ssl 的 log 層級至 `DEBUG`：

```
echo "logger.com.floragunn.searchguard.ssl: DEBUG" >> /etc/elasticsearch/logging.yml
```

此時，至少在 `/etc/elasticsearch/elasticsearch.yml` 加入以下設定：

```bash
searchguard.enable: true
security.manager.enabled: false
searchguard.authcz.admin_dn:
  - "CN=admin,OU=client,O=PIC,l=Taipei, C=TW"
```

然後 restart Elasticsearch 服務：

```bash
systemctl restart elasticsearch
```

## 2. 準備相關檔案

我們在此步驟要先 git clone 「[search-guard-ssl](https://github.com/floragunncom/search-guard-ssl/) 」專案，因為我們需要此專案中的 `searchguard-ssl-config-template.yml` 檔案與 `example-pki-scripts` 目錄裡的一些 shell scripts，才能完成後續的工作。

```bash
mkdir -p /root/tmp && cd /root/tmp
git clone https://github.com/floragunncom/search-guard-ssl.git
```

請先依據您的需要，編輯 `search-guard-ssl/searchguard-ssl-config-template.yml`。（建議你可以先參考一下[我設定完成的 elasticsearch.yml](https://github.com/desp0916/InstallSearchGuard/blob/master/etc/elasticsearch.yml)，比較看看我修改了哪些地方）。然後，再把這些設定加入 `/etc/elasticsearch/elasticsearch.yml`。

再來，也請先依據您的需要，編輯 `/usr/share/elasticsearch/sg_scripts` 下的這四個檔案：

 - `etc/root-ca.conf`
 - `etc/signing-ca.conf`
 - `gen_client_cert.sh`
 - `gen_node_cert.sh`

同樣地，建議你也可以先參考官方 wiki「[Create your own Root CA](https://github.com/floragunncom/search-guard-ssl/wiki/Create-your-own-Root-CA)」與[我修改後的內容](https://github.com/desp0916/InstallSearchGuard/tree/master/sg_scripts) 。然後，再把這個目錄複製為 `/usr/share/elasticsearch/sg_scripts`：

```
cp -r search-guard-ssl/example-pki-scripts /usr/share/elasticsearch/sg_scripts
```

接著，再檢查一下 `/usr/share/elasticsearch/sg_scripts/` 目錄下的檔案：

```
cd /usr/share/elasticsearch/
tree -L 3 sg_scripts/
sg_scripts/
├── clean.sh
├── etc
│   ├── root-ca.conf
│   └── signing-ca.conf
├── example.sh
├── gen_client_node_cert.sh
├── gen_node_cert.sh
└── gen_root_ca.sh
```

## 3. 產生 truststore 與 keystore：

一般來說，如果要產生自我簽署的 SSL 憑證（self-signed certificate），首先就是要自己當 Root CA，然後用 Root CA 的憑證去簽署 node 的 csr，產生 node 的 crt、pem 與 jks。之後，nodes 之間的傳輸通道才能使用 SSL 加密（透過每個 node 上的 keystore 與 trustore）。keystore 包含了讓其他 nodes 識別 node 本身的憑證，truststore 則包含了自己信任的其他節點憑證 —— 這點可藉由將根憑證加入 truststore 來達成。所以這個步驟主要就是在產生這些 keystore 和 trustore。

產生 Root CA 憑證與 truststore：

```bash
cd /usr/share/elasticsearch/sg_tools/
./clean.sh  # 如果你是初次產生 Root CA 與憑證，此步驟可省略；
            # 這個指令是用來刪除之前產生的檔案與目錄的。
./gen_root_ca.sh capass changeit     # 產生 Root CA。「capass」是 Root CA 的憑證加密密碼，「changeit」則是 truststore
                                     # 的憑證加密密碼，請依您的需要修改。執行後，會在目前路徑下產生 ca/、certs/、crl/
                                     # 與 truststore.jks 等目錄與檔案。
cp truststore.jks /etc/elasticsearch # 將 truststore.jks 複製到 elasticsearch 設定目錄下。
```

產生某 node 的 keystore，這裡使用 `localhost` 做為 node name。正常來說，這個值應該和 `/elasticsearch/elasticsearch.yml` 的 `node.name` 設定一樣： 

```bash
./gen_node_cert.sh localhost changeit capass       # 產生某 node 的憑證與 keystore。執行後，會在目前路徑下產生
                                                   # node-localhost.csr、node-localhost-keystore.jks 和
                                                   # node-localhost-keystore.p12 和 node-localhost-signed.pem 共 4 個檔案。
cp node-localhost-keystore.jks /etc/elasticsearch  # 將 node-localhost-keystore.jks 複製到 elasticsearch 設定目錄下。
```

繼續產生 client(user) 的 keystore，這裡以 `admin` 為例：

```bash
./gen_client_node_cert.sh admin kspass capass    # 產生某 client node 的憑證與 keystore。執行後，會在目前路徑下產生
                                                 # admin.crt.pem、admin.key.pem、admin-keystore.p12、admin-keystore.jks、
                                                 # admin-signed.pem、admin.csr 共 6 個檔案。
```

這裡有一件事情要特別提醒一下，就是這裡產生的憑證都只有*兩年*的有效期限。所以，請務必記得快要到期前，要重新產生憑證喔！

您可以使用以下指令來檢視憑證的有效日期：

```bash
openssl x509 -in admin-signed.pem -text -noout
openssl x509 -in node-localhost-signed.pem -text -noout
```

## 4. 建立一個 `admin` user

為 Search Guard 新增一個 user 其實滿麻煩的。這邊以 `admin` 為例，一步一步解說。

首先你要用 `/plugins/search-guard-2/tools/hash.sh` 來為 `admin` 的密碼產生 hash code（如果 `hash.sh` 不能執行，記得要先 `chmod u+x hash.sh`）：

```bash
/usr/share/elasticsearch/plugins/search-guard-2/tools/hash.sh -p adminpass
$2a$12$F6CgjzWuB5wLMgqLJPuf4.gaXxPNqDhOBDcgq2OMKp6ll1tpD.B.W
```

記下這組 hash code（當然不是叫你背下來，你可以先複製貼上到 notepad 裡）。

編輯 `/etc/elasticsearch/elasticsearch.yml`，確認有以下這個設定，這代表 `admin` 帳號具有管理權限（可以讀寫 `searchguard` 索引）：

```bash
searchguard.authcz.admin_dn:
  - "CN=admin,OU=client,O=PIC,l=Taipei, C=TW"
```

切換目錄到 `/usr/share/elasticsearch/plugins/search-guard-2/sgconfig` 下，編輯以下檔案：

sg_internal_users.yml，把剛剛記下來的那組 hash code 複製過來：

```yaml
admin:
  hash: $2a$12$F6CgjzWuB5wLMgqLJPuf4.gaXxPNqDhOBDcgq2OMKp6ll1tpD.B.W
  roles:
    - sg_admin
```

sg_roles_mapping.yml

```yaml
sg_admin:
  backendroles:
    - vulcanadmin
  users:
    - admin
```

sg_roles.yml

```yaml
sg_admin:
  cluster:
    - CLUSTER_ALL
  indices:
    '*':
      '*':
        - ALL
```

## 5. 上傳設定檔並建立  `searchguard` 索引

切換目錄到 `/user/share/elasticsearch/` 下，執行以下指令（如果 `sgadmin.sh` 不能執行，記得要先 `chmod u+x `sgadmin.sh）：

```bash
plugins/search-guard-2/tools/sgadmin.sh \
  -cd plugins/search-guard-2/sgconfig   \
  -ks sg_scripts/admin-keystore.jks     \
  -ts sg_scripts/truststore.jks         \
  -kspass kspass -tspass capass         \
  -nhnv -nrhn
```

`sgadmin.sh` 會以 `admin` 這個帳號與密碼，把 `sgconfig/` 目錄下的 5 個檔案上傳到 cluster，並建立（或更新） `searchguard` 索引： 

 - `sg_config.yml`
 - `sg_roles.yml`
 - `sg_roles_mapping.yml`
 - `sg_internal_users.yml`
 - `sg_action_groups.yml`

這 5 個檔案就是所謂的「[Dynamic configuration](https://github.com/floragunncom/search-guard)」。

如果一切順利的話，你會看到如下的訊息：

```bash
Connect to localhost:9300
searchguard index does not exists, attempt to create it ... done
populate config ...
Will update 'config' with plugins/search-guard-2/sgconfig/sg_config.yml
   SUCC Configuration for 'config' created or updated
Will update 'roles' with plugins/search-guard-2/sgconfig/sg_roles.yml
   SUCC Configuration for 'roles' created or updated
Will update 'rolesmapping' with plugins/search-guard-2/sgconfig/sg_roles_mapping.yml
   SUCC Configuration for 'rolesmapping' created or updated
Will update 'internalusers' with plugins/search-guard-2/sgconfig/sg_internal_users.yml
   SUCC Configuration for 'internalusers' created or updated
Will update 'actiongroups' with plugins/search-guard-2/sgconfig/sg_action_groups.yml
   SUCC Configuration for 'actiongroups' created or updated
Wait a short time ...
Done with success
```

## 6. 檢查驗證安裝成功

檢查 SSL 是否安裝成功：

```bash
curl -XGET -k -u admin:adminpass "https://localhost:9200/_searchguard/sslinfo?pretty"
# 1. 如果安裝失敗，你應該不會看到任何訊息。
# 2. 如果 Open SSL 設定成功，會看到如下訊息：
{
  "principal" : null,
  "peer_certificates" : "0",
  "ssl_protocol" : "TLSv1.2",
  "ssl_cipher" : "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
  "ssl_openssl_available" : true,
  "ssl_openssl_version" : 268439647,
  "ssl_openssl_version_string" : "OpenSSL 1.0.1e-fips 11 Feb 2013",
  "ssl_openssl_non_available_cause" : "",
  "ssl_provider_http" : "OPENSSL",
  "ssl_provider_transport_server" : "OPENSSL",
  "ssl_provider_transport_client" : "OPENSSL"
}
# 3. 如果 Open SSL 啟用失敗，會降回使用 JKS：
{
  "principal" : null,
  "peer_certificates" : "0",
  "ssl_protocol" : "TLSv1.2",
  "ssl_cipher" : "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
  "ssl_openssl_available" : false,
  "ssl_openssl_version" : -1,
  "ssl_openssl_version_string" : null,
  "ssl_openssl_non_available_cause" : "java.lang.IllegalArgumentException: Failed to load any of the given libraries: [netty-tcnative-linux-x86_64, netty-tcnative-linux-x86_64-fedora, netty-tcnative]",
  "ssl_provider_http" : "JDK",
  "ssl_provider_transport_server" : "JDK",
  "ssl_provider_transport_client" : "JDK"
}
```

檢視是否有 `searchgaurd` 這個索引：

```bash
curl -XGET -k -u admin:adminpass "https://localhost:9200/_cat/indices?pretty"
yellow open logstash-2015.05.19 5 1   4624 0    18mb    18mb
yellow open logstash-2015.05.18 5 1   4631 0  18.3mb  18.3mb
yellow open bank                5 1   1000 0 442.6kb 442.6kb
yellow open accounts            5 1      0 0    805b    805b
yellow open searchguard         1 1
yellow open .kibana             1 1      3 0  16.5kb  16.5kb
yellow open shakespeare         5 1 111396 0  18.8mb  18.8mb
yellow open logstash-2015.05.20 5 1   4750 0    19mb    19mb
```

最後，也可檢視  `searchgaurd` 這個索引的內容：

```bash
 curl -XGET -k -u admin:adminpass "https://localhost:9200/searchguard/?pretty" | less
{
  "searchguard" : {
    "aliases" : { },
    "mappings" : {
      "config" : {
        "properties" : {
          "searchguard" : {
            "properties" : {
 :
 :
```

## 7. 參考文件：

以下是我參考的一些文件：

  - [search-guard](https://github.com/floragunncom/search-guard)
  - [search-guard Wiki](https://github.com/floragunncom/search-guard/wiki)
  - [search-guard-ssl](https://github.com/floragunncom/search-guard-ssl)
  - [search-guard-ssl Wiki](https://github.com/floragunncom/search-guard-ssl/wiki)
  - [Search Guard for Elasticsearch 2 is coming Februar 2016    ](https://groups.google.com/forum/#!topic/search-guard/orEvYx3liH8)

## 8. 常見問題：

### Q1: 如何設定 user 的權限？

A: 其實在 `/usr/share/elasticsearch/plugins/search-guard-2/sgconfig/sg_internal_users.yml` 裡，已經有內建很多個 users 了，但這應該只是一個範例檔而已，因為作者在 `sg_roles.yml` 和 `sg_roles_mapping.yml` 的設定似乎對不起來。建議你可以自行稍微花些時間瞭解這些檔案之間的關聯與設定方式，或者參考 Shield 的文件（因為 Search Guard 似乎在模仿 Shield），本文就不詳述了（其實我自己也還沒有搞很清楚啦，呵呵～）。

### Q2: 如何 troubleshooting？

A: 安裝設定過程中，建議可以另開一個 terminal，然後 `tail -F /var/log/elasticsearch/elasticsearch.log`，隨時觀看 log 訊息。

