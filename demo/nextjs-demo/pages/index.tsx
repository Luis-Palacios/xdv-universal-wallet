import Head from "next/head";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import styles from "../styles/Home.module.css";
import { DIDManager } from '../../../lib';
import Web3Modal from 'web3modal';
import WalletConnectProvider from "@walletconnect/web3-provider";

export default function Home() {
  const onConnectClick = async () => {
    const CERAMIC_URL = 'dev-ceramic.paidnetwork.com'; // TODO: set as env variable
    const providerOptions = {
      walletconnect: {
        package: WalletConnectProvider,
        options: {
          infuraId: 'bce97999b34a4b759ca27229313f96ec' // TODO: set as env variable
        }
      },
    }
    const web3Modal = new Web3Modal({
      providerOptions: providerOptions,
      cacheProvider: false
    })
    const provider = await web3Modal.connect();
    const addresses = await provider.enable()
    debugger;

    const didManager = new DIDManager();
    // let address = '';
    // if (provider.accounts)
    // // walletconnect
    //   address = provider.accounts[0];
    // else{
    //   // metamask
    //   address =  provider.selectedAddress;
    // }
    const externalWeb3 =  await didManager.create3IDWeb3External(provider, addresses[0]); // TODO: send ceramic as third argument, 
    await externalWeb3.did.authenticate();

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
