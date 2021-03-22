import { useState } from "react";
import Head from "next/head";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import styles from "../styles/Home.module.css";

export default function IndividualConnect() {
  const onMetaMaskClick = () => {
    toast.success("Connected Metamask");
  };

  const onXDVClick = () => {
    toast.success("Connected XDV");
  };

  const onBinanceClick = () => {
    toast.success("Connected Binace");
  };
  return (
    <div className={styles.container}>
      <Head>
        <title>Nextjs Universal Wallet Demo</title>
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <main className={styles.main}>
        <button className="main-btn" onClick={onMetaMaskClick}>Connect MetaMask</button>
        <br />
        <button className="main-btn" onClick={onXDVClick}>Connect XDV Wallet</button>
        <br />
        <button className="main-btn" onClick={onBinanceClick}>Connect Binance</button>
        <br />
        <a href="/">Try multy connect here</a>
      </main>
      <ToastContainer />
    </div>
  );
}
