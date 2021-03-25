import Head from "next/head";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { useEffect, useState } from "react";
import styles from "../styles/Home.module.css";
// import { DIDManager } from '../../../lib';

import Web3Modal from "web3modal";
import WalletConnectProvider from "@walletconnect/web3-provider";

import ThreeIdResolver from "@ceramicnetwork/3id-did-resolver";
import Ceramic from "@ceramicnetwork/http-client";
import { DID } from "dids";
import { IDX } from "@ceramicstudio/idx";
import { ThreeIdConnect, EthereumAuthProvider } from "3id-connect";

const CERAMIC_URL = "http://localhost:7007"; // TODO: set as env variable
const providerOptions = {
  walletconnect: {
    package: WalletConnectProvider,
    options: {
      infuraId: "bce97999b34a4b759ca27229313f96ec", // TODO: set as env variable
    },
  },
};

export default function Home() {
  const onConnectClick = async () => {
    const ethProvider = await new Web3Modal({
      providerOptions: providerOptions,
      cacheProvider: false,
    }).connect();

    const addresses = await ethProvider.enable();

    debugger;
    const authProvider = new EthereumAuthProvider(ethProvider, addresses[0]);
    const threeIdConnect = new ThreeIdConnect();
    await threeIdConnect.connect(authProvider);
    const didProvider =  threeIdConnect.getDidProvider();

    debugger;
    const ceramic = new Ceramic(CERAMIC_URL);
    ceramic.setDIDProvider(didProvider);
    
    // ceramic.setDIDProvider
    // const did = new DID({
    //   provider: threeIdConnect.getDidProvider(),
    //   resolver: ThreeIdResolver.getResolver(ceramic),
    // });

    await ceramic.did.authenticate();

    console.log(ceramic.did.id);

    const jws = await ceramic.did.createJWS({ hello: "world" });
    console.log(jws);
    const aliases = {
      secretNotes: 'kjzl6cwe1jw14b03qkg5rl0dmq44yjayvku5yvca69fhokexzodwpbjb2zgqusj'
    }
    window.idx = new IDX({ ceramic, aliases });
    window.ceramic = ceramic;
    window.did = ceramic.did.id;

    // const externalWeb3 = await didManager.create3IDWeb3External(
    //   provider,
    //   addresses[0]
    // ); // TODO: send ceramic as third argument,
    // await externalWeb3.did.authenticate();

    toast.success("Connected");
  };

  return (
    <div className={styles.container}>
      <Head>
        <title>Nextjs Universal Wallet Demo</title>
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <main className={styles.main}>
        <button className="main-btn" onClick={onConnectClick}>
          Connect
        </button>
        <br />
        <a href="/indivitual-connect">Try individual connect here</a>
      </main>
      <ToastContainer />
    </div>
  );
}
