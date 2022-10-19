# fluent-bit vkcloudlogs output plugin

This plugin works with fluent-bit's go plugin interface. You can use fluent-bit vkcloudlogs to ship logs into vk cloudlogging service.

# Usage
Install Fluent Bit, i.e. https://docs.fluentbit.io/manual/installation/linux/ubuntu

```bash
$ cd cloudlogs-fluent-bit
$ make
go build -ldflags "-X main.BuildGitVersion=v0.1 -X main.BuildTime=20220715" -buildmode=c-shared -o vkcloudlogs-fluent-bit.so .
$ /opt/fluent-bit/bin/fluent-bit -i dummy -e ./vkcloudlogs-fluent-bit.so -o vkcloudlogs -p"server_host_port=cloudlogs.mcs.mail.ru:443" -p"user_id=<cut>" -p"password=<cut>" -p"project_id=<cut>" -p"auth_url=https://infra.mail.ru:35357/v3/"
Fluent Bit v1.9.6
* Copyright (C) 2015-2022 The Fluent Bit Authors
* Fluent Bit is a CNCF sub-project under the umbrella of Fluentd
* https://fluentbit.io

[2022/08/03 14:19:19] [ info] [fluent bit] version=1.9.6, commit=, pid=342223
[2022/08/03 14:19:19] [ info] [storage] version=1.2.0, type=memory-only, sync=normal, checksum=disabled, max_chunks_up=128
[2022/08/03 14:19:19] [ info] [cmetrics] version=0.3.5
2022-08-03T14:19:19.877+0300	INFO	Init VK Cloudlog Fluent Bit Plugin  compiled at 20220803 on go1.17.11
[2022/08/03 14:19:19] [ info] [sp] stream processor started
```

# Config parameters

| **Key**         | **Description**                                                                                                                       | **How to get** |
|-----------------|---------------------------------------------------------------------------------------------------------------------------------------|-|
| service_id      | (optional) service_id с которым писать логи. по умолчанию default                                                                     | |
| group_id        | (optional) group_id с которым писать логи по умолчанию Tag из fluentbit                                                               | |
| group_id_key    | (optional) поле из которого брать group_id. при отсутствие значение group_id                                                          | |
| stream_id       | (optional) stream_id с которым писать логи. по умолчанию пустой                                                                       | |
| stream_id_key   | (optional) поле из которого брать stream_id. при отсутствие значение stream_id                                                        | |
| message_key     | (optional) поле из которого брать сообщение для логов. по умолчанию "message"                                                         | |
| level_key       | (optional) поле из которого уровень логирования для записи. по умолчанию "level"                                                      | |
| default_level   | (optional) уровень логирования для записи при отсутствия поля "level_key". по умолчанию "debug"                                       | |
| default_payload | (optional) дополнительные поля которые нужно сохранить в payload. по умолчанию не добавлет полей                                      | |
| server_host_port| (required) хост и порт куда сохранять логи.                                                                                           | cloudlogs.mcs.mail.ru:443 |
| tls_on          | (optional) включен ли tls на адресе server_host_port. доступны значения true включен, false выключен. по умолчаню включен             | |
| tls_verify      | (optional) проверять ли сертификат tls на адресе server_host_port. доступны значения true проверять, false не проверять. по умолчаню проверять | |
| <авторизация>   | см. Authorization                                                                                                                     | |


# Authorization parameters

| **Key**    | **Description**                                                                                              | **How to get** |
|------------|--------------------------------------------------------------------------------------------------------------|-|
| auth_url   | (required) Адрес сервиса авторизации                                                                         | Auth URL на  https://mcs.mail.ru/app/any/project/keys |
| project_id | (required) Идентификатор проекта в которым будут хранится логи                                               | Project ID на https://mcs.mail.ru/app/any/project/keys |
| key_file   | (optional) json файл где храняться user_id и password. Альтернатива указания user_id/password                | |
| user_id    | (optional) user_id под которым будут писаться логи. Альтернатива указания user_name и key_file               | |
| user_name  | (optional) user_name в домене users под которым будут писаться логи. Альтернаива указания user_id и key_file | |
| password   | (optional) пароль пользователя под которым будут писаться логи. Альтернатива указания key_file               | |
| internal   | (optional) технические логи сервисов. доступны значения true включен, false выключен. по умолчаню выключен   | |


# Prerequisites

* Go 1.17
* gcc (for cgo)

## Building

```bash
$ make
```

## Useful links

* [Install FluentBit on Ubuntu](https://docs.fluentbit.io/manual/installation/linux/ubuntu)
* [fluent-bit-go](https://github.com/fluent/fluent-bit-go)
* [FluentBit GO plugin guide](https://docs.fluentbit.io/manual/development/golang-output-plugins)
