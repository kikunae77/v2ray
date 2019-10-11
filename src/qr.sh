_qr_create() {
	local vmess="vmess://$(cat /etc/v2ray/vmess_qr.json | base64 -w 0)"
	local link="https://233boy.github.io/tools/qr.html#${vmess}"
	echo
	echo "---------- V2Ray QR코드 링크 V2RayNG v0.4.1+ / Kitsunebi 이상에 사용 가능 -------------"
	echo
	echo -e ${cyan}$link${none}
	echo
	echo
	echo -e "$red 스캔 결과를 꼭 확인하세요 (V2RayNG 이외) $none"
	echo
	echo
	echo " V2Ray 클라이언트 사용 강좌(중국어): https://233v2.com/post/4/"
	echo
	echo
	rm -rf /etc/v2ray/vmess_qr.json
}
_ss_qr() {
	local ss_link="ss://$(echo -n "${ssciphers}:${sspass}@${ip}:${ssport}" | base64 -w 0)#233v2.com_ss_${ip}"
	local link="https://233boy.github.io/tools/qr.html#${ss_link}"
	echo
	echo "---------- Shadowsocks QR코드 링크 -------------"
	echo
	echo -e "$yellow 링크 = $cyan$link$none"
	echo
	echo -e " 주의...$red Shadowsocks Win 4.0.6 $none클라이언트는 QR코드 인식이 불가능합니다."
	echo
	echo
}
