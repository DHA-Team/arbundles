# ANS-104 Bundles

A low level library for creating, editing, reading and verifying bundles.

See [ANS-104](https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md) for more details.

## Installing the library

Using npm:

`npm install @dha-team/arbundles`

Using yarn:

`yarn add @dha-team/arbundles`

## Creating bundles

```ts
import { bundleAndSignData, createData } from "@dha-team/arbundles";

const dataItems = [createData("some data"), createData("some other data")];

const signer = new ArweaveSigner(jwk);

const bundle = await bundleAndSignData(dataItems, signer);
```

## Signing with a NEAR wallet

NEAR browser wallets can only sign [NEP-413](https://github.com/near/NEPs/blob/master/neps/nep-0413.md) messages, so items they sign use signature type 413. The wallet's key must be known before an item is created, so call `setPublicKey()` once after connecting. It asks the wallet to sign a probe message.

```ts
import { createData, InjectedNearSigner } from "@dha-team/arbundles";

const signer = new InjectedNearSigner(wallet); // any wallet with NEP-413 signMessage, e.g. from @hot-labs/near-connect
await signer.setPublicKey();

const item = createData("some data", signer);
await item.sign(signer);
```

The signed payload has no `callbackUrl`, so wallets that always add one (MyNearWallet signs the page URL) cannot sign these items; the signer then throws rather than produce an invalid item.
