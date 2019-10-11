[[ -z $ip ]] && get_ip
_v2_args() {
	header="none"
	if [[ $is_path ]]; then
		_path="/$path"
	else
		_path="/"
	fi
	case $v2ray_transport in
	1 | 18)
		net="tcp"
		;;
	2 | 19)
		net="tcp"
		header="http"
		host="www.baidu.com"
		;;
	3 | 4 | 20)
		net="ws"
		;;
	5)
		net="h2"
		;;
	6 | 21)
		net="kcp"
		;;
	7 | 22)
		net="kcp"
		header="utp"
		;;
	8 | 23)
		net="kcp"
		header="srtp"
		;;
	9 | 24)
		net="kcp"
		header="wechat-video"
		;;
	10 | 25)
		net="kcp"
		header="dtls"
		;;
	11 | 26)
		net="kcp"
		header="wireguard"
		;;
	12 | 27)
		net="quic"
		;;
	13 | 28)
		net="quic"
		header="utp"
		;;
	14 | 29)
		net="quic"
		header="srtp"
		;;
	15 | 30)
		net="quic"
		header="wechat-video"
		;;
	16 | 31)
		net="quic"
		header="dtls"
		;;
	17 | 32)
		net="quic"
		header="wireguard"
		;;
	esac
}

_v2_info() {
	echo
	echo
	echo "---------- V2Ray 설정 정보 -------------"
	if [[ $v2ray_transport == [45] ]]; then
		if [[ ! $caddy ]]; then
			echo
			echo -e " $red주의!$none$yellow TLS 자동설정을 사용하세요... 강좌(중국어): https://233v2.com/post/3/$none"
		fi
		echo
		echo -e "$yellow 주소 (Address) = $cyan${domain}$none"
		echo
		echo -e "$yellow 포트 (Port) = ${cyan}443${none}"
		echo
		echo -e "$yellow 사용자ID (User ID / UUID) = $cyan${v2ray_id}$none"
		echo
		echo -e "$yellow Alter ID (Alter Id) = ${cyan}${alterId}${none}"
		echo
		echo -e "$yellow 프로토콜 (Network) = ${cyan}${net}$none"
		echo
		echo -e "$yellow 위장 종류 (header type) = ${cyan}${header}$none"
		echo
		echo -e "$yellow 위장 도메인 (host) = ${cyan}${domain}$none"
		echo
		echo -e "$yellow 경로 (path) = ${cyan}${_path}$none"
		echo
		echo -e "$yellow TLS (Enable TLS) = ${cyan}켬$none"
		echo
		if [[ $ban_ad ]]; then
			echo " 참고: 광고차단기능 사용 중.."
			echo
		fi
	else
		echo
		echo -e "$yellow 주소 (Address) = $cyan${ip}$none"
		echo
		echo -e "$yellow 포트 (Port) = $cyan$v2ray_port$none"
		echo
		echo -e "$yellow 사용자ID (User ID / UUID) = $cyan${v2ray_id}$none"
		echo
		echo -e "$yellow Alter ID (Alter Id) = ${cyan}${alterId}${none}"
		echo
		echo -e "$yellow 프로토콜 (Network) = ${cyan}${net}$none"
		echo
		echo -e "$yellow 위장 종류 (header type) = ${cyan}${header}$none"
		echo
	fi
	if [[ $v2ray_transport -ge 18 ]] && [[ $ban_ad ]]; then
		echo " 참고: 동적포트 사용 중......광고차단기능 사용 중..."
		echo
	elif [[ $v2ray_transport -ge 18 ]]; then
		echo " 참고: 동적포트 사용 중..."
		echo
	elif [[ $ban_ad ]]; then
		echo " 참고: 광고차단기능 사용 중.."
		echo
	fi
	echo "---------- END -------------"
	echo
	echo "V2Ray 클라이언트 사용 강좌(중국어): https://233v2.com/post/4/"
	echo
	echo -e "참고: $cyan v2ray url $none명령어로 vmess URL 링크 / $cyan v2ray qr $none 명령어로 QR코드 링크를 생성할 수 있습니다."
	echo
}
