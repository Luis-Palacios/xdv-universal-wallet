import { DIDDocumentBuilder } from '../did/DIDDocumentBuilder';
import { ethers } from 'ethers';
import { expect } from 'chai';
import { JOSEService } from './JOSEService';
import { JWTService } from './JWTService';
import { KeyConvert, X509Info } from './KeyConvert';
import { LDCryptoTypes } from './LDCryptoTypes';
import { Wallet } from './Wallet';
let localStorage = {};

    async function bootstrap() {
      const result = await Wallet.createWeb3Provider('https://ropsten.infura.io/v3/79110f2241304162b087759b5c49cf99', 
    {passphrase:'1234'})
    console.log (result)  
    
  }


bootstrap()
