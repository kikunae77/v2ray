[[ -z $ip ]] && get_ip
if [[ $shadowsocks ]]; then
	local ss="ss://$(echo -n "${ssciphers}:${sspass}@${ip}:${ssport}" | base64 -w 0)#233v2.com_ss_${ip}"
	echo
	echo "---------- Shadowsocks 설정 정보 -------------"
	echo
	echo -e "$yellow 서버 주소 = $cyan${ip}$none"
	echo
	echo -e "$yellow 서버 포트 = $cyan$ssport$none"
	echo
	echo -e "$yellow 암호 = $cyan$sspass$none"
	echo
	echo -e "$yellow 암호화 프로토콜 = $cyan${ssciphers}$none"
	echo
	echo -e "$yellow SS 링크 = ${cyan}$ss$none"
	echo
	echo -e " 참고:$red Shadowsocks Win 4.0.6 $none클라이언트는 SS 링크를 식별하지 못합니다."
	echo
	echo -e " 참고: $cyan v2ray ssqr $none 명령어로 Shadowsocks QR코드를 생성할 수 있습니다."	
	echo
fi
