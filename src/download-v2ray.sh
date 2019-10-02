_get_latest_version() {
	v2ray_latest_ver="$(curl -H 'Cache-Control: no-cache' -s https://api.github.com/repos/v2ray/v2ray-core/releases/latest | grep 'tag_name' | cut -d\" -f4)"

	if [[ ! $v2ray_latest_ver ]]; then
		echo
		echo -e " $red V2Ray 최신 버전을 가져오는데 실패했습니다!!!$none"
		echo
		echo -e " 아래 명령어를 테스트 해보시기 바랍니다. : $green echo 'nameserver 8.8.8.8' >/etc/resolv.conf $none"
		echo
		echo " 그리고 스크립트를 다시 실행해주세요...."
		echo
		exit 1
	fi
}

_download_v2ray_file() {
	_get_latest_version
	[[ -d /tmp/v2ray ]] && rm -rf /tmp/v2ray
	mkdir -p /tmp/v2ray
	v2ray_tmp_file="/tmp/v2ray/v2ray.zip"
	v2ray_download_link="https://github.com/v2ray/v2ray-core/releases/download/$v2ray_latest_ver/v2ray-linux-${v2ray_bit}.zip"

	if ! wget --no-check-certificate -O "$v2ray_tmp_file" $v2ray_download_link; then
		echo -e "
        $red V2Ray 다운로드에 실패했습니다.. VPS의 인터넷 연결 상황이 안 좋은 것 같습니다.... 다시 실행해 주세요...$none
        " && exit 1
	fi

	unzip $v2ray_tmp_file -d "/tmp/v2ray/"
	mkdir -p /usr/bin/v2ray
	cp -f "/tmp/v2ray/v2ray" "/usr/bin/v2ray/v2ray"
	chmod +x "/usr/bin/v2ray/v2ray"
	echo "alias v2ray=$_v2ray_sh" >>/root/.bashrc
	cp -f "/tmp/v2ray/v2ctl" "/usr/bin/v2ray/v2ctl"
	chmod +x "/usr/bin/v2ray/v2ctl"
}

_install_v2ray_service() {
	if [[ $systemd ]]; then
		cp -f "/tmp/v2ray/systemd/v2ray.service" "/lib/systemd/system/"
		sed -i "s/on-failure/always/" /lib/systemd/system/v2ray.service
		systemctl enable v2ray
	else
		apt-get install -y daemon
		cp "/tmp/v2ray/systemv/v2ray" "/etc/init.d/v2ray"
		chmod +x "/etc/init.d/v2ray"
		update-rc.d -f v2ray defaults
	fi
}

_update_v2ray_version() {
	_get_latest_version
	if [[ $v2ray_ver != $v2ray_latest_ver ]]; then
		echo
		echo -e " $green 새 버전을 발견했습니다.... 업데이트를 진행합니다.......$none"
		echo
		_download_v2ray_file
		do_service restart v2ray
		echo
		echo -e " $green 업데이트를 성공했습니다.... 현재 V2Ray 버전: ${cyan}$v2ray_latest_ver$none"
		echo
		echo -e " $yellow 참고사항: 문제 발생을 막기위해 V2Ray 클라이언트는 가능하면 서버와 동일한 버전을 사용하시기 바랍니다.$none"
		echo
	else
		echo
		echo -e " $green 새 버전이 없습니다....$none"
		echo
	fi
}

_mkdir_dir() {
	mkdir -p /var/log/v2ray
	mkdir -p /etc/v2ray
}
