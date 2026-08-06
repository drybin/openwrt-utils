.DEFAULT_GOAL := help

.PHONY: help test check

help:
	@printf '%s\n' \
		'openwrt-utils' \
		'' \
		'Команды разработки:' \
		'  make help   Показать эту справку' \
		'  make test   Запустить unit-тесты' \
		'  make check  Проверить Python, shell-синтаксис и запустить тесты' \
		'' \
		'Основные команды:' \
		'  ./scripts/vpn --help' \
		'  ./scripts/openwrt-vless --help' \
		'  ./scripts/openwrt-dns --help' \
		'' \
		'Установка CLI на OpenWrt:' \
		'  scp scripts/openwrt-vless root@openwrt:/usr/bin/vpn' \
		'  ssh root@openwrt chmod +x /usr/bin/vpn'

test:
	python3 -m unittest discover -s tests -v

check:
	python3 -m py_compile vpn_tool.py tests/test_vpn_tool.py
	sh -n scripts/vpn scripts/openwrt-vless scripts/openwrt-dns
	$(MAKE) test
