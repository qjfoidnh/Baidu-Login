package baidulogin

import (
	"fmt"
	"github.com/astaxie/beego/session"
	"github.com/qjfoidnh/BaiduPCS-Go/pcsutil"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

// registerBaiduClient 为 sess 如果没有 BaiduClient , 就添加
func registerBaiduClient(sess *session.Store) {
	if (*sess).Get("baiduclinet") == nil { // 找不到 cookie 储存器
		(*sess).Set("baiduclinet", NewBaiduClinet())
	}
}

// getBaiduClient 查找该 sessionID 下是否存在 BaiduClient
func getBaiduClient(sessionID string) (*BaiduClient, error) {
	sessionStore, err := globalSessions.GetSessionStore(sessionID)
	if err != nil {
		return NewBaiduClinet(), err
	}
	clientInterface := sessionStore.Get("baiduclinet")
	switch value := clientInterface.(type) {
	case *BaiduClient:
		return value, nil
	default:
		return NewBaiduClinet(), fmt.Errorf("Unknown session type: %s", value)
	}
}

// parseTemplate 自己写的简易 template 解析器
func parseTemplate(content string, rep map[string]string) string {
	for k, v := range rep {
		content = strings.Replace(content, "{{."+k+"}}", v, 1)
	}
	return content
}

// parsePhoneAndEmail 抓取绑定百度账号的邮箱和手机号并插入至 json 结构
func (lj *LoginJSON) parsePhoneAndEmail(bc *BaiduClient) {
	if lj.Data.GotoURL == "" {
		return
	}

	_, err := bc.Fetch("GET", lj.Data.VerifyURL, nil, nil)
	if err != nil {
		fmt.Println(err)
	}
	rawAuthID := regexp.MustCompile("&authid=(.+?)&").FindStringSubmatch(lj.Data.VerifyURL)
	if len(rawAuthID) > 1 {
		lj.Data.AuthID = string(rawAuthID[1])
	}
	rawToken := regexp.MustCompile(`[\?&]token=(.+?)&`).FindStringSubmatch(lj.Data.VerifyURL)
	if len(rawToken) > 1 {
		lj.Data.Token = rawToken[1]
	}
	rawU := regexp.MustCompile(`[\?&]u=(.+?)&`).FindStringSubmatch(lj.Data.VerifyURL)
	if len(rawU) > 1 {
		if u, err := url.Parse(rawU[1]); err == nil {
			lj.Data.U = u.Path
		}
	}
	return
}

// parseCookies 解析 STOKEN, PTOKEN, BDUSS 并插入至 json 结构.
func (lj *LoginJSON) parseCookies(targetURL, body string, jar *cookiejar.Jar) {
	url, _ := url.Parse(targetURL)
	tokenRegexp := regexp.MustCompile(`<stoken>netdisk#([a-z0-9A-Z\-]+)<`)
	params := tokenRegexp.FindStringSubmatch(body)
	cookies := jar.Cookies(url)
	cookies_statics := 0
	for _, cookie := range cookies {
		switch cookie.Name {
		case "BDUSS":
			lj.Data.BDUSS = cookie.Value
			cookies_statics++
		case "PTOKEN":
			lj.Data.PToken = cookie.Value
			cookies_statics++
		case "STOKEN":
			lj.Data.SToken = cookie.Value
			cookies_statics++
		}
	}
	if len(params)==2 {
		lj.Data.SToken = params[1]
	} else {
		if cookies_statics == 3 {
			fmt.Println("消息: 验证成功, 开始重新登录, 可能需要继续输入两次图片验证码")
		} else {
			fmt.Println("Warning: 未获取到正确的Stoken, 登录状态部分异常, 建议重试或以其他方式登录")
		}
	}
	lj.Data.CookieString = pcsutil.GetURLCookieString(targetURL, jar) // 插入 cookie 字串
}
