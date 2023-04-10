import nodeFetch from "node-fetch";
import fetchCookie from "fetch-cookie";
import HttpsProxyAgent from 'https-proxy-agent';

function validateContentType(response, contentType) {
    if (response.headers.get("content-type")?.indexOf(contentType) === -1) throw new Error(`wrong response type: expected ${contentType}`);
}

class MyCookiejar {
    constructor(puid) {
        this.puid = puid
        this.realCookieJar = new fetchCookie.toughCookie.CookieJar();
    }

    async getCookieString(currentUrl) {
        return `_puid=${this.puid}; ` + await this.realCookieJar.getCookieString(currentUrl);
    }

    setCookie(cookieString, currentUrl) {
        return this.realCookieJar.setCookie(cookieString, currentUrl)
    }
}

function validateStatuses(response, statuses) {
    if (!statuses.includes(response.status)) throw new Error(`wrong status code: expected ${statuses}, but actual ${response.status}`);
}

export class ChatGPTAuthTokenService {
    constructor(email, password, puid) {
        this.email = email;
        this.password = password;
        this.puid = puid
        this.accessToken = null;
        this.sessionToken = null;
        const cookieJar = new MyCookiejar(puid)
        // cookieJar.setCookie("_puid=" + puid, "*")
        const fetch = fetchCookie(nodeFetch, cookieJar);
        this.proxyAgent = new HttpsProxyAgent('http://127.0.0.1:7890');

        this.fetch = (url, options) => {
            return fetch(url, {...options, agent: this.proxyAgent})
        }


        this.userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
    }

    async getToken() {
        try {
            if (this.accessToken) return this.accessToken;

            this.accessToken = await this._getAccessToken();
            return this.accessToken;
        } catch (e) {
            throw new Error("could not get token");
        }
    }

    async refreshToken() {
        try {
            this.accessToken = null;
            return this.getToken();
        } catch (e) {
            throw new Error("could not refresh token");
        }
    }

    async getAccessToken() {
        if (!this.accessToken) {
            await this.stepZero();
        }

        try {
            const accessToken = await this._getAccessToken();
            return accessToken;
        } catch (e) {
            // return this.stepZero();
            throw e;
        }
    }

    /**
     * In part two, We make a request to https://chat.openai.com/api/auth/csrf and grab a fresh csrf token
     * @param email
     * @param password
     * @param puid
     * @returns {Promise<null|*>}
     */
    async stepZero() {
        const url = "https://chat.openai.com/api/auth/csrf"
        const headers = {
            "Host": "chat.openai.com",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "User-Agent": this.userAgent,
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Referer": "https://chat.openai.com/auth/login",
            "Accept-Encoding": "gzip, deflate, br",
        }
        const response = await this.fetch(url, {
            method: "GET", headers
        });
        validateStatuses(response, [200]);
        validateContentType(response, "application/json");


        const data = await response.json();
        return this.stepOne(data.csrfToken);
    }

    async stepOne(csrf) {

        // We reuse the token from part to make a request to /api/auth/signin/auth0?prompt=login

        const url = "https://chat.openai.com/api/auth/signin/auth0?prompt=login"

        const payload = `callbackUrl=%2F&csrfToken=${csrf}&json=true`
        const headers = {
            "Host": "chat.openai.com",
            "User-Agent": this.userAgent,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Sec-Gpc": "1",
            "Accept-Language": "en-US,en;q=0.8",
            "Origin": "https://chat.openai.com",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://chat.openai.com/auth/login",
            "Accept-Encoding": "gzip, deflate",
        }
        const response = await this.fetch(url, {method: 'POST', headers, body: payload})
        validateStatuses(response, [200]);
        validateContentType(response, "application/json");
        const responseJson = await response.json()
        const nextUrl = responseJson.url
        if (nextUrl === "https://chat.openai.com/api/auth/error?error=OAuthSignin" || nextUrl.includes("error")) {
            throw new Error(`Step One: You have been rate limited. Please try again later.`);
        }
        await this.stepTwo(nextUrl)
    }

    async stepTwo(url) {
        //         We make a GET request to url

        const headers = {
            "Host": "auth0.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": this.userAgent,
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://chat.openai.com/",
        }
        const response = await this.fetch(url, {
            method: "GET", headers
        })
        validateStatuses(response, [200, 302])
        const text = await response.text()

        const regex = /state=(.*)/g;
        let state = text.match(regex)[0]
        state = state.split('"')[0].substring(6)
        await this.stepThree(state);
    }

    // We use the state to get the login page
    async stepThree(state) {
        const url = `https://auth0.openai.com/u/login/identifier?state=${state}`
        const headers = {
            "Host": "auth0.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": this.userAgent,
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://chat.openai.com/",
        }
        const response = await this.fetch(url, {methods: "GET", headers: headers})
        validateStatuses(response, [200])
        await this.stepFour(state)
    }

    // We make a POST request to the login page with the captcha, email
    async stepFour(state) {
        const url = `https://auth0.openai.com/u/login/identifier?state=${state}`
        const emailUrlEncoded = encodeURIComponent(this.email)

        const payload = `state=${state}&username=${emailUrlEncoded}&js-available=false&webauthn-available=true&is-brave=false&webauthn-platform-available=true&action=default`

        const headers = {
            "Host": "auth0.openai.com",
            "Origin": "https://auth0.openai.com",
            "Connection": "keep-alive",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": this.userAgent,
            "Referer": `https://auth0.openai.com/u/login/identifier?state=${state}`,
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        const response = await this.fetch(url, {
            method: "POST", headers, body: payload
        })
        validateStatuses(response, [200, 302])
        await this.stepFive(state)
    }

    async stepFive(state) {
        const url = `https://auth0.openai.com/u/login/password?state=${state}`
        const emailUrlEncoded = encodeURIComponent(this.email)
        const passwordUrlEncoded = encodeURIComponent(this.password)
        const payload = `state=${state}&username=${emailUrlEncoded}&password=${passwordUrlEncoded}&action=default`
        const headers = {
            "Host": "auth0.openai.com",
            "Origin": "https://auth0.openai.com",
            "Connection": "keep-alive",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": this.userAgent,
            "Referer": `https://auth0.openai.com/u/login/password?state=${state}`,
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        const response = await this.fetch(url, {
            method: "POST", headers, body: payload, follow: 0, redirect: 'manual'
        })
        validateStatuses(response, [302])
        const nextUrl = response.headers.get("location")
        await this.stepSix(state, nextUrl)
    }

    async stepSix(oldState, redirectUrl) {
        const url = redirectUrl
        // const url = "https://auth0.openai.com" + redirectUrl
        const headers = {
            "Host": "auth0.openai.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": this.userAgent,
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Referer": `https://auth0.openai.com/u/login/password?state=${oldState}`,
        }
        const response = await this.fetch(url, {
            method: "GET", headers, redirect: 'manual', follow: 0
        })
        validateStatuses(response, [302])
        const nextUrl = response.headers.get("location")
        await this.stepSeven(nextUrl, url)
    }

    async stepSeven(redirectUrl, previousUrl) {
        const url = redirectUrl
        const headers = {
            "Host": "chat.openai.com",
            "Accept": "application/json",
            "Connection": "keep-alive",
            "User-Agent": this.userAgent,
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Referer": previousUrl,
        }
        const response = await this.fetch(url, {
            method: "GET", headers
        })
        validateStatuses(response, [200])
    }

    async _getAccessToken() {
        const response = await this.fetch("https://chat.openai.com/api/auth/session",)
        validateStatuses(response, [200])
        const data = await response.json()
        this.accessToken = data.accessToken
    }
}

const tokenService = new ChatGPTAuthTokenService('chatgpt01@chinalawinfo.com', 'chatgptbdyh$', 'user-GB0WyDamvcuSHpg1DBak6ZQR:1681097123-C%2BRbERhtMiy%2FFVxu2rlp93ELU%2FK29ROmHEi3dwDkrkU%3D')
await tokenService.getAccessToken()
await tokenService.getToken()
