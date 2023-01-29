const fs = require('fs');
const https = require('https');
const ora = require('ora');
const ansiColors = require('ansi-colors');
const path = require('path');
const _ = require('lodash');
const inquirer = require('inquirer');
const fg = require('fast-glob');
const detect = require('detect-port');
const request = require('superagent');
const execa = require('execa');

async function execCommandAsync(cmd, args, options) {
    const { stdout } = await execa(cmd, args, options);
    return stdout;
}

function calcDef(fileList, ext) {
    const selFile = _.find(fileList, (name) => name.indexOf(ext) !== -1);
    if (selFile) {
        return selFile;
    }
    return null;
}

function startSpinner(msg) {
    return ora(msg).start();
}

/**
 *
 * @returns {https.Server<typeof IncomingMessage, typeof ServerResponse>}
 */
function createhttpsServer(options, port) {
    return new Promise((r, e) => {
        const server = https.createServer(options, (req, res) => {
            res.writeHead(200);
            res.end('hello world\n');
        });
        server.listen(port);
        server.on('error', (error) => e(error));
        server.on('listening', () => r(server));
    });
}

async function reqSever(port, { ca, cert, key, pfx }) {
    return request.post(`https://localhost:${port}`).key(key).cert(cert).ca(ca).pfx(pfx);
}

async function httpsChecker(result) {
    const ca = fs.readFileSync(result['ca']);
    const cert = fs.readFileSync(result['cert']);
    const key = fs.readFileSync(result['key']);
    const pfx = fs.readFileSync(result['pfx']);
    const port = await detect(4300);
    const server = await createhttpsServer(
        {
            pfx,
            passphrase: result['pfxPass'],
        },
        port
    );
    server.close();

    const server2 = await createhttpsServer(
        {
            key,
            cert,
            ca,
        },
        port
    );
    server2.close();

    await execCommandAsync('./openssl-lib/openssl.exe', [
        'verify',
        '-no-CAfile',
        '-no-CApath',
        '-partial_chain',
        '-trusted',
        result['ca'],
        result['cert'],
    ]);
}

async function main() {
    let sslSpinner = null;
    try {
        console.log('===============================');
        console.log('==         SSL Checker       ==');
        console.log('===============================');
        console.log('');

        let fileList = await fg(['*'], { dot: false });
        const exeInfo = path.parse(process.execPath);
        fileList = _.filter(fileList, (name) => name !== exeInfo.base);
        if (fileList.length === 0) {
            throw new Error('Not found any file');
        }
        const questions = [
            {
                type: 'list',
                name: 'key',
                message: 'Select the SSL KEY',
                choices: fileList,
                default: calcDef(fileList, '.key'),
            },
            {
                type: 'list',
                name: 'cert',
                message: 'Select the SSL CERTIFICATE',
                choices: fileList,
                default: calcDef(fileList, '.crt'),
            },
            {
                type: 'list',
                name: 'ca',
                message: 'Select the SSL CHAIN (CA)',
                choices: fileList,
                default: calcDef(fileList, '.ca-bundle'),
            },
            {
                type: 'list',
                name: 'pfx',
                message: 'Select the SSL PFX (CA)',
                choices: fileList,
                default: calcDef(fileList, '.pfx'),
            },
            {
                type: 'password',
                name: 'pfxPass',
                message: 'PFX Password: ',
            },
            {
                type: 'password',
                name: 'pfxConfirm',
                message: 'PFX Confirm Password: ',
            },
        ];
        const result = await inquirer.prompt(questions);
        console.log('===============================');
        console.log('');

        if (result.pfxPass !== result.pfxConfirm) {
            throw new Error('PFX confirm password does not match');
        }

        sslSpinner = startSpinner(ansiColors.yellowBright('Checking SSL'));

        await httpsChecker(result);

        sslSpinner.succeed(ansiColors.greenBright('SSL OK!'));
    } catch (error) {
        if (sslSpinner) {
            sslSpinner.fail(ansiColors.redBright(error.message));
        } else {
            console.log(ansiColors.redBright(' ' + error.message));
        }
    }
    try {
        console.log('');
        console.log('==== Press any key to exit ====');

        process.stdin.setRawMode(true);
        process.stdin.resume();
        process.stdin.on('data', process.exit.bind(process, 0));
    } catch (error) {
        // error
    }
}

main();
