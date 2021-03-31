import Head from 'next/head'
import styles from '../styles/Home.module.css'
import { DIDManager,  } from '../../../lib'

export default function Home() {
  const onConnect = async () => {
    // @ts-ignore
    const addresses = await window.ethereum.enable();
    
    
    const didManager = new DIDManager();
    // @ts-ignore
    const externalWeb3 =  await didManager.create3IDWeb3External(window.ethereum, addresses[0]); // TODO: send ceramic as third argument, 
    await externalWeb3.did.authenticate();
    
  }
  return (
    <div className={styles.container}>
      <Head>
        <title>Create Next App</title>
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <main className={styles.main}>
        <button onClick={onConnect}>Connect</button>
      </main>

      <footer className={styles.footer}>
        <a
          href="https://vercel.com?utm_source=create-next-app&utm_medium=default-template&utm_campaign=create-next-app"
          target="_blank"
          rel="noopener noreferrer"
        >
          Powered by{' '}
          <img src="/vercel.svg" alt="Vercel Logo" className={styles.logo} />
        </a>
      </footer>
    </div>
  )
}
