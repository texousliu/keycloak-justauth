# keycloak-justauth
keycloak 集成 Github、Gitee、微博、钉钉、百度、Coding、腾讯云开发者平台、OSChina、支付宝、QQ、微信、淘宝、Google、Facebook、抖音、领英、小米、微软、今日头条、Teambition、StackOverflow、Pinterest、人人、华为、企业微信、酷家乐、Gitlab、美团、饿了么和推特等第三方平台的授权登录。

已验证 Keycloak 16.1.1 / 17.0.1 (legacy) / 18.0.2 (legacy)

即开即用镜像: ztelliot/keycloak-justauth:latest / ghcr.io/ztelliot/keycloak-justauth:latest (16.1.1)

可以指定 tag 为 17.0.1 / 18.0.2 来使用基于 legacy 构建的镜像

由于 Keycloak 官方在 17.0.0 起基于 Quarkus，Quarkus 目录结构发生较大变动，故新镜像暂由使用老 WildFly 发行版的 legacy 镜像构建
