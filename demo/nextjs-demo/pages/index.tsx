import Head from "next/head";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import styles from "../styles/Home.module.css";
import { UniversalWallet } from '../../../lib'

export default function Home() {
  const onConnectClick = async () => {
    const universalWallet = new UniversalWallet();
    const demo = await universalWallet.unlock('1234', 'abcdef123456');
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
