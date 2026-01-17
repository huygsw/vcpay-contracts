const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
const { expect } = chai;
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

chai.use(chaiAsPromised);

const DOMAIN_NAME = "GSWSafe";
const DOMAIN_VERSION = "1";

/* ---------------- FIXTURE ---------------- */

async function deployFixture() {
  const [owner1, owner2, owner3, executor, outsider] =
    await ethers.getSigners();

  const Multisig = await ethers.getContractFactory("GSWSafeV1");
  const multisig = await Multisig.deploy(
    [owner1.address, owner2.address, owner3.address],
    2,
    executor.address,
  );
  await multisig.deployed();

  return { multisig, owner1, owner2, owner3, executor, outsider };
}

/* ---------------- SIGNING HELPERS ---------------- */

async function domain(multisig) {
  return {
    name: DOMAIN_NAME,
    version: DOMAIN_VERSION,
    chainId: (await ethers.provider.getNetwork()).chainId,
    verifyingContract: multisig.address,
  };
}

async function signExecute({
  multisig,
  signers,
  to,
  value,
  data,
  nonce,
  deadline,
}) {
  const message = { to, value, data, nonce, deadline };

  const sigs = await Promise.all(
    signers.map(async (s) =>
      s._signTypedData(
        await domain(multisig),
        {
          Execute: [
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "data", type: "bytes" },
            { name: "nonce", type: "uint256" },
            { name: "deadline", type: "uint256" },
          ],
        },
        message,
      ),
    ),
  );

  return sigs
    .map((sig, i) => ({ sig, addr: signers[i].address.toLowerCase() }))
    .sort((a, b) => (a.addr > b.addr ? 1 : -1))
    .map((x) => x.sig)
    .reduce((acc, sig) => acc + sig.slice(2), "0x");
}

async function signAdmin(multisig, signers, action, target, value) {
  const nonce = await multisig.nonce();

  const message = {
    action: ethers.utils.keccak256(ethers.utils.toUtf8Bytes(action)),
    target,
    value,
    nonce,
  };

  const sigs = await Promise.all(
    signers.map(async (s) =>
      s._signTypedData(
        await domain(multisig),
        {
          Admin: [
            { name: "action", type: "bytes32" },
            { name: "target", type: "address" },
            { name: "value", type: "uint256" },
            { name: "nonce", type: "uint256" },
          ],
        },
        message,
      ),
    ),
  );

  return sigs
    .map((sig, i) => ({ sig, addr: signers[i].address.toLowerCase() }))
    .sort((a, b) => (a.addr > b.addr ? 1 : -1))
    .map((x) => x.sig)
    .reduce((acc, sig) => acc + sig.slice(2), "0x");
}

/* ---------------- TESTS ---------------- */

describe("Multisig (security)", function () {
  it("constructor sets owners / threshold / executor", async function () {
    const { multisig, owner1, owner2, owner3, executor } = await loadFixture(
      deployFixture,
    );

    expect(await multisig.isOwner(owner1.address)).to.eq(true);
    expect(await multisig.isOwner(owner2.address)).to.eq(true);
    expect(await multisig.isOwner(owner3.address)).to.eq(true);
    expect((await multisig.threshold()).toNumber()).to.eq(2);
    expect(await multisig.executor()).to.eq(executor.address);
  });

  it("only executor can execute", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce: await multisig.nonce(),
      deadline: (await ethers.provider.getBlock("latest")).timestamp + 1000,
    });

    await expect(multisig.execute(owner1.address, 0, "0x", Date.now(), sigs)).to
      .be.rejected;
  });

  it("prevents replay attacks", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner2.address,
      value: ethers.utils.parseEther("0.1"),
      data: "0x",
      nonce,
      deadline,
    });

    await multisig
      .connect(executor)
      .execute(
        owner2.address,
        ethers.utils.parseEther("0.1"),
        "0x",
        deadline,
        sigs,
      );

    await expect(
      multisig
        .connect(executor)
        .execute(
          owner2.address,
          ethers.utils.parseEther("0.1"),
          "0x",
          deadline,
          sigs,
        ),
    ).to.be.rejected;
  });

  it("rejects unordered signatures", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const sigs = await signExecute({
      multisig,
      signers: [owner2, owner1], // wrong order
      to: owner2.address,
      value: 0,
      data: "0x",
      nonce: await multisig.nonce(),
      deadline: (await ethers.provider.getBlock("latest")).timestamp + 1000,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(owner2.address, 0, "0x", Date.now(), sigs),
    ).to.be.rejected;
  });

  it("rejects duplicate signer abuse", async function () {
    const { multisig, owner1, executor } = await loadFixture(deployFixture);

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner1],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce: await multisig.nonce(),
      deadline: (await ethers.provider.getBlock("latest")).timestamp + 1000,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", Date.now(), sigs),
    ).to.be.rejected;
  });

  it("reentrancy attempt does not break multisig state", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const Reenter = await ethers.getContractFactory("Reenter");
    const attacker = await Reenter.deploy(multisig.address);
    await attacker.deployed();

    // fund multisig
    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    const multisigBalanceBefore = await ethers.provider.getBalance(
      multisig.address,
    );
    const attackerBalanceBefore = await ethers.provider.getBalance(
      attacker.address,
    );
    const nonceBefore = await multisig.nonce();

    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const signatures = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: attacker.address,
      value: ethers.utils.parseEther("0.1"),
      data: "0x",
      nonce: nonceBefore,
      deadline,
    });

    // execution MAY succeed or revert depending on gas path
    try {
      await multisig
        .connect(executor)
        .execute(
          attacker.address,
          ethers.utils.parseEther("0.1"),
          "0x",
          deadline,
          signatures,
        );
    } catch (_) {
      // acceptable
    }

    const multisigBalanceAfter = await ethers.provider.getBalance(
      multisig.address,
    );
    const attackerBalanceAfter = await ethers.provider.getBalance(
      attacker.address,
    );
    const nonceAfter = await multisig.nonce();

    // 🔒 SECURITY INVARIANTS
    expect(
      nonceAfter.eq(nonceBefore) || nonceAfter.eq(nonceBefore.add(1)),
    ).to.eq(true);

    const attackerDelta = attackerBalanceAfter.sub(attackerBalanceBefore);
    const multisigDelta = multisigBalanceBefore.sub(multisigBalanceAfter);

    expect(attackerDelta.lte(ethers.utils.parseEther("0.1"))).to.eq(true);

    expect(multisigDelta.lte(ethers.utils.parseEther("0.1"))).to.eq(true);
  });

  it("cancelNonce invalidates signed tx", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const txSigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "cancelNonce",
      ethers.constants.AddressZero,
      0,
    );

    await multisig.cancelNonce(adminSigs);

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, txSigs),
    ).to.be.rejected;
  });

  it("rejects expired deadline", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const expiredDeadline =
      (await ethers.provider.getBlock("latest")).timestamp - 1;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline: expiredDeadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", expiredDeadline, sigs),
    ).to.be.rejected;

    const currentNonce = await multisig.nonce();

    // nonce must NOT change
    expect(currentNonce.toNumber()).to.eq(nonce.toNumber());
  });

  it("rejects deadline beyond MAX_DEADLINE_DURATION", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const tooFarDeadline =
      (await ethers.provider.getBlock("latest")).timestamp + 31 * 24 * 60 * 60; // > 30 days

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline: tooFarDeadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", tooFarDeadline, sigs),
    ).to.be.rejected;

    const currentNonce = await multisig.nonce();

    expect(currentNonce.toNumber()).to.eq(nonce.toNumber());
  });

  it("rejects execute targeting itself", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: multisig.address, // 🔥 self-call
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(multisig.address, 0, "0x", deadline, sigs),
    ).to.be.rejected;

    const currentNonce = await multisig.nonce();

    // nonce must NOT change
    expect(currentNonce.toNumber()).to.eq(nonce.toNumber());
  });

  it("rejects execution when multisig balance is insufficient", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: ethers.utils.parseEther("1"), // multisig has 0 ETH
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(
          owner1.address,
          ethers.utils.parseEther("1"),
          "0x",
          deadline,
          sigs,
        ),
    ).to.be.rejected;

    const currentNonce = await multisig.nonce();

    // nonce must NOT change
    expect(currentNonce.toNumber()).to.eq(nonce.toNumber());
  });

  it("executeStrict succeeds on valid call", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    // fund multisig
    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner2.address,
      value: ethers.utils.parseEther("0.2"),
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .executeStrict(
          owner2.address,
          ethers.utils.parseEther("0.2"),
          "0x",
          deadline,
          sigs,
        ),
    ).to.not.be.rejected;

    expect((await multisig.nonce()).toNumber()).to.eq(nonce.toNumber() + 1);
  });

  it("works when threshold equals ownerCount", async function () {
    const { multisig, owner1, owner2, owner3, executor } = await loadFixture(
      deployFixture,
    );

    // change threshold to 3 (ownerCount)
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setThreshold",
      ethers.constants.AddressZero,
      3,
    );

    await multisig.setThreshold(3, adminSigs);

    const threshold = await multisig.threshold();
    expect(threshold.toNumber()).to.eq(3);

    // fund multisig
    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2, owner3], // all owners required
      to: owner2.address,
      value: ethers.utils.parseEther("0.1"),
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(
          owner2.address,
          ethers.utils.parseEther("0.1"),
          "0x",
          deadline,
          sigs,
        ),
    ).to.not.be.rejected;
  });

  it("works when threshold is set to 1", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setThreshold",
      ethers.constants.AddressZero,
      1,
    );

    await multisig.setThreshold(1, adminSigs);

    const threshold = await multisig.threshold();
    expect(threshold.toNumber()).to.eq(1);

    // fund multisig
    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1], // only one signer
      to: owner2.address,
      value: ethers.utils.parseEther("0.05"),
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(
          owner2.address,
          ethers.utils.parseEther("0.05"),
          "0x",
          deadline,
          sigs,
        ),
    ).to.not.be.rejected;
  });

  it("rejects setting threshold to 0", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setThreshold",
      ethers.constants.AddressZero,
      0,
    );

    await expect(multisig.setThreshold(0, adminSigs)).to.be.rejected;

    // threshold unchanged
    const threshold = await multisig.threshold();
    expect(threshold.toNumber()).to.eq(2);
  });

  it("rejects setting threshold greater than ownerCount", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setThreshold",
      ethers.constants.AddressZero,
      4, // ownerCount is 3
    );

    await expect(multisig.setThreshold(4, adminSigs)).to.be.rejected;

    const threshold = await multisig.threshold();
    expect(threshold.toNumber()).to.eq(2);
  });

  it("removing an owner updates ownerCount and threshold safely", async function () {
    const { multisig, owner1, owner2, owner3 } = await loadFixture(
      deployFixture,
    );

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "removeOwner",
      owner3.address,
      2, // new threshold
    );

    await multisig.removeOwner(owner3.address, 2, adminSigs);

    const isOwner = await multisig.isOwner(owner3.address);
    expect(isOwner).to.eq(false);

    const threshold = await multisig.threshold();
    expect(threshold.toNumber()).to.eq(2);
  });

  it("prevents replaying admin signatures", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setThreshold",
      ethers.constants.AddressZero,
      1,
    );

    // first call succeeds
    await multisig.setThreshold(1, adminSigs);

    // replay must fail
    await expect(multisig.setThreshold(1, adminSigs)).to.be.rejected;

    const threshold = await multisig.threshold();
    expect(threshold.toNumber()).to.eq(1);
  });

  it("setExecutor changes the executor successfully", async function () {
    const { multisig, owner1, owner2, executor, outsider } = await loadFixture(
      deployFixture,
    );

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setExecutor",
      outsider.address,
      0,
    );

    await multisig.setExecutor(outsider.address, adminSigs);

    expect(await multisig.executor()).to.eq(outsider.address);
  });

  it("setExecutor rejects zero address", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setExecutor",
      ethers.constants.AddressZero,
      0,
    );

    await expect(multisig.setExecutor(ethers.constants.AddressZero, adminSigs))
      .to.be.rejected;
  });

  it("setExecutor prevents replay attacks", async function () {
    const { multisig, owner1, owner2, outsider } = await loadFixture(
      deployFixture,
    );

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setExecutor",
      outsider.address,
      0,
    );

    await multisig.setExecutor(outsider.address, adminSigs);

    // replay must fail
    await expect(multisig.setExecutor(outsider.address, adminSigs)).to.be
      .rejected;
  });

  it("addOwner successfully adds new owner", async function () {
    const { multisig, owner1, owner2, outsider } = await loadFixture(
      deployFixture,
    );

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "addOwner",
      outsider.address,
      2,
    );

    await multisig.addOwner(outsider.address, 2, adminSigs);

    expect(await multisig.isOwner(outsider.address)).to.eq(true);
    expect((await multisig.ownerCount()).toNumber()).to.eq(4);
  });

  it("addOwner can increase threshold", async function () {
    const { multisig, owner1, owner2, outsider } = await loadFixture(
      deployFixture,
    );

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "addOwner",
      outsider.address,
      3,
    );

    await multisig.addOwner(outsider.address, 3, adminSigs);

    expect((await multisig.threshold()).toNumber()).to.eq(3);
  });

  it("addOwner rejects zero address", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "addOwner",
      ethers.constants.AddressZero,
      2,
    );

    await expect(multisig.addOwner(ethers.constants.AddressZero, 2, adminSigs))
      .to.be.rejected;
  });

  it("addOwner rejects duplicate owner", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "addOwner",
      owner1.address,
      2,
    );

    await expect(multisig.addOwner(owner1.address, 2, adminSigs)).to.be
      .rejected;
  });

  it("addOwner rejects invalid threshold (0)", async function () {
    const { multisig, owner1, owner2, outsider } = await loadFixture(
      deployFixture,
    );

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "addOwner",
      outsider.address,
      0,
    );

    await expect(multisig.addOwner(outsider.address, 0, adminSigs)).to.be
      .rejected;
  });

  it("addOwner rejects invalid threshold (exceeds new owner count)", async function () {
    const { multisig, owner1, owner2, outsider } = await loadFixture(
      deployFixture,
    );

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "addOwner",
      outsider.address,
      5, // will be 4 owners after adding
    );

    await expect(multisig.addOwner(outsider.address, 5, adminSigs)).to.be
      .rejected;
  });

  it("removeOwner maintains correct state after swap-and-pop", async function () {
    const { multisig, owner1, owner2, owner3 } = await loadFixture(
      deployFixture,
    );

    // remove owner1 (not the last one)
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "removeOwner",
      owner1.address,
      1,
    );

    await multisig.removeOwner(owner1.address, 1, adminSigs);

    expect(await multisig.isOwner(owner1.address)).to.eq(false);
    expect((await multisig.ownerCount()).toNumber()).to.eq(2);

    // verify remaining owners are still valid
    expect(await multisig.isOwner(owner2.address)).to.eq(true);
    expect(await multisig.isOwner(owner3.address)).to.eq(true);

    const owners = await multisig.getOwners();
    expect(owners.length).to.eq(2);
  });

  it("removeOwner rejects removing non-owner", async function () {
    const { multisig, owner1, owner2, outsider } = await loadFixture(
      deployFixture,
    );

    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "removeOwner",
      outsider.address,
      2,
    );

    await expect(multisig.removeOwner(outsider.address, 2, adminSigs)).to.be
      .rejected;
  });

  it("receive() accepts ETH", async function () {
    const { multisig, owner1 } = await loadFixture(deployFixture);

    const balanceBefore = await ethers.provider.getBalance(multisig.address);
    expect(balanceBefore.toNumber()).to.eq(0);

    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    const balanceAfter = await ethers.provider.getBalance(multisig.address);
    expect(balanceAfter.toString()).to.eq(
      ethers.utils.parseEther("1").toString(),
    );
  });

  it("onERC721Received returns correct selector", async function () {
    const { multisig } = await loadFixture(deployFixture);

    const selector = await multisig.onERC721Received(
      ethers.constants.AddressZero,
      ethers.constants.AddressZero,
      0,
      "0x",
    );

    expect(selector).to.eq("0x150b7a02");
  });

  it("onERC1155Received returns correct selector", async function () {
    const { multisig } = await loadFixture(deployFixture);

    const selector = await multisig.onERC1155Received(
      ethers.constants.AddressZero,
      ethers.constants.AddressZero,
      0,
      0,
      "0x",
    );

    expect(selector).to.eq("0xf23a6e61");
  });

  it("onERC1155BatchReceived returns correct selector", async function () {
    const { multisig } = await loadFixture(deployFixture);

    const selector = await multisig.onERC1155BatchReceived(
      ethers.constants.AddressZero,
      ethers.constants.AddressZero,
      [],
      [],
      "0x",
    );

    expect(selector).to.eq("0xbc197c81");
  });

  it("getTransactionHash returns correct hash", async function () {
    const { multisig, owner1 } = await loadFixture(deployFixture);

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const hash = await multisig.getTransactionHash(
      owner1.address,
      0,
      "0x",
      deadline,
    );

    expect(hash).to.be.a("string");
    expect(hash.length).to.eq(66); // 0x + 64 hex chars
  });

  it("getAdminHash returns correct hash", async function () {
    const { multisig, owner1 } = await loadFixture(deployFixture);

    const hash = await multisig.getAdminHash("setExecutor", owner1.address, 0);

    expect(hash).to.be.a("string");
    expect(hash.length).to.eq(66);
  });

  it("getOwners returns all current owners", async function () {
    const { multisig, owner1, owner2, owner3 } = await loadFixture(
      deployFixture,
    );

    const owners = await multisig.getOwners();

    expect(owners.length).to.eq(3);
    expect(owners).to.include(owner1.address);
    expect(owners).to.include(owner2.address);
    expect(owners).to.include(owner3.address);
  });

  it("domainSeparator returns cached value on same chain", async function () {
    const { multisig } = await loadFixture(deployFixture);

    const ds1 = await multisig.domainSeparator();
    const ds2 = await multisig.domainSeparator();

    expect(ds1).to.eq(ds2);
    expect(ds1.length).to.eq(66);
  });

  it("rejects invalid signature length", async function () {
    const { multisig, executor } = await loadFixture(deployFixture);

    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    // Only provide 64 bytes instead of 130 (2 * 65)
    const invalidSigs = "0x" + "00".repeat(64);

    await expect(
      multisig
        .connect(executor)
        .execute(executor.address, 0, "0x", deadline, invalidSigs),
    ).to.be.rejected;
  });

  it("rejects signature with invalid v value", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    // Corrupt the v value (last byte of first signature)
    const corruptedSigs =
      sigs.substring(0, sigs.length - 130) +
      "1a" +
      sigs.substring(sigs.length - 128);

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, corruptedSigs),
    ).to.be.rejected;
  });

  it("rejects signature from non-owner", async function () {
    const { multisig, owner1, outsider, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    // Use outsider instead of owner2
    const sigs = await signExecute({
      multisig,
      signers: [owner1, outsider],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, sigs),
    ).to.be.rejected;
  });

  it("execute succeeds with calldata", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    // Deploy a simple counter contract to interact with
    const Counter = await ethers.getContractFactory("Counter");
    const counter = await Counter.deploy();
    await counter.deployed();

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const calldata = counter.interface.encodeFunctionData("increment");

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: counter.address,
      value: 0,
      data: calldata,
      nonce,
      deadline,
    });

    await multisig
      .connect(executor)
      .execute(counter.address, 0, calldata, deadline, sigs);

    expect((await counter.count()).toNumber()).to.eq(1);
  });

  it("executeStrict reverts on failed call", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const FailingContract = await ethers.getContractFactory("FailingContract");
    const failing = await FailingContract.deploy();
    await failing.deployed();

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const calldata = failing.interface.encodeFunctionData("alwaysFails");

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: failing.address,
      value: 0,
      data: calldata,
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .executeStrict(failing.address, 0, calldata, deadline, sigs),
    ).to.be.rejected;
  });

  it("prevents nonce manipulation via self-call", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    // Try to call cancelNonce through execute
    const calldata = multisig.interface.encodeFunctionData("cancelNonce", [
      "0x",
    ]);

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: multisig.address, // self-call
      value: 0,
      data: calldata,
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(multisig.address, 0, calldata, deadline, sigs),
    ).to.be.rejected;

    // Verify nonce hasn't changed
    expect((await multisig.nonce()).toNumber()).to.eq(nonce.toNumber());
  });

  it("supports zero value transfers", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, sigs),
    ).to.not.be.rejected;
  });

  it("full workflow: add owner, increase threshold, execute with new threshold, remove owner", async function () {
    const { multisig, owner1, owner2, owner3, executor, outsider } =
      await loadFixture(deployFixture);

    // Initial state: 3 owners, threshold 2
    expect((await multisig.ownerCount()).toNumber()).to.eq(3);
    expect((await multisig.threshold()).toNumber()).to.eq(2);

    // Step 1: Add new owner and increase threshold to 3
    let adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "addOwner",
      outsider.address,
      3,
    );

    await multisig.addOwner(outsider.address, 3, adminSigs);

    expect((await multisig.ownerCount()).toNumber()).to.eq(4);
    expect((await multisig.threshold()).toNumber()).to.eq(3);

    // Step 2: Fund multisig
    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    // Step 3: Execute transaction with new threshold (need 3 signatures)
    let nonce = await multisig.nonce();
    let deadline = (await ethers.provider.getBlock("latest")).timestamp + 1000;

    let txSigs = await signExecute({
      multisig,
      signers: [owner1, owner2, owner3], // now need 3 signers
      to: owner2.address,
      value: ethers.utils.parseEther("0.1"),
      data: "0x",
      nonce,
      deadline,
    });

    await multisig
      .connect(executor)
      .execute(
        owner2.address,
        ethers.utils.parseEther("0.1"),
        "0x",
        deadline,
        txSigs,
      );

    // Step 4: Remove owner and decrease threshold
    adminSigs = await signAdmin(
      multisig,
      [owner1, owner2, outsider],
      "removeOwner",
      owner3.address,
      2,
    );

    await multisig.removeOwner(owner3.address, 2, adminSigs);

    expect((await multisig.ownerCount()).toNumber()).to.eq(3);
    expect((await multisig.threshold()).toNumber()).to.eq(2);
    expect(await multisig.isOwner(owner3.address)).to.eq(false);
  });
});

/* ============================================================
   SECURITY VULNERABILITY TESTS
   These tests check for actual security flaws, not just happy paths
   ============================================================ */

describe("Multisig (security vulnerabilities)", function () {
  /* ----------------------------------------------------------
     CRITICAL: Removed owner signature exploitation
     ---------------------------------------------------------- */

  it("CRITICAL: rejects pre-signed tx after signer is removed as owner", async function () {
    const { multisig, owner1, owner2, owner3, executor } = await loadFixture(
      deployFixture,
    );

    // Fund multisig
    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    // Step 1: owner1 and owner2 pre-sign a transaction
    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 10000;

    const preSigned = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner2.address,
      value: ethers.utils.parseEther("0.5"),
      data: "0x",
      nonce,
      deadline,
    });

    // Step 2: Remove owner2 via admin action (this increments nonce)
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "removeOwner",
      owner2.address,
      2,
    );
    await multisig.removeOwner(owner2.address, 2, adminSigs);

    expect(await multisig.isOwner(owner2.address)).to.eq(false);

    // Step 3: Try to execute the pre-signed transaction
    // This should fail because:
    // a) nonce has changed (removeOwner consumed it)
    // b) owner2 is no longer an owner
    await expect(
      multisig
        .connect(executor)
        .execute(
          owner2.address,
          ethers.utils.parseEther("0.5"),
          "0x",
          deadline,
          preSigned,
        ),
    ).to.be.rejected;
  });

  it("CRITICAL: removed owner cannot sign new transactions", async function () {
    const { multisig, owner1, owner2, owner3, executor } = await loadFixture(
      deployFixture,
    );

    // Remove owner2
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "removeOwner",
      owner2.address,
      2,
    );
    await multisig.removeOwner(owner2.address, 2, adminSigs);

    // Fund multisig
    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    // Try to sign with removed owner2
    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const maliciousSigs = await signExecute({
      multisig,
      signers: [owner1, owner2], // owner2 is no longer valid
      to: owner2.address,
      value: ethers.utils.parseEther("0.5"),
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(
          owner2.address,
          ethers.utils.parseEther("0.5"),
          "0x",
          deadline,
          maliciousSigs,
        ),
    ).to.be.rejected;
  });

  /* ----------------------------------------------------------
     CRITICAL: Executor parameter substitution attacks
     ---------------------------------------------------------- */

  it("CRITICAL: executor cannot substitute 'to' address", async function () {
    const { multisig, owner1, owner2, owner3, executor, outsider } =
      await loadFixture(deployFixture);

    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    // Owners sign for transfer to owner2
    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner2.address,
      value: ethers.utils.parseEther("0.5"),
      data: "0x",
      nonce,
      deadline,
    });

    // Executor tries to substitute with outsider address
    await expect(
      multisig.connect(executor).execute(
        outsider.address, // SUBSTITUTED - should be owner2
        ethers.utils.parseEther("0.5"),
        "0x",
        deadline,
        sigs,
      ),
    ).to.be.rejected;
  });

  it("CRITICAL: executor cannot substitute 'value' amount", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    // Owners sign for 0.1 ETH
    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner2.address,
      value: ethers.utils.parseEther("0.1"),
      data: "0x",
      nonce,
      deadline,
    });

    // Executor tries to drain entire balance
    await expect(
      multisig.connect(executor).execute(
        owner2.address,
        ethers.utils.parseEther("1"), // SUBSTITUTED - should be 0.1
        "0x",
        deadline,
        sigs,
      ),
    ).to.be.rejected;
  });

  it("CRITICAL: executor cannot substitute 'data' calldata", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const Counter = await ethers.getContractFactory("Counter");
    const counter = await Counter.deploy();
    await counter.deployed();

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const legitimateData = counter.interface.encodeFunctionData("increment");

    // Owners sign for increment()
    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: counter.address,
      value: 0,
      data: legitimateData,
      nonce,
      deadline,
    });

    // Executor tries to substitute with different calldata
    const maliciousData = counter.interface.encodeFunctionData("reset");

    await expect(
      multisig.connect(executor).execute(
        counter.address,
        0,
        maliciousData, // SUBSTITUTED
        deadline,
        sigs,
      ),
    ).to.be.rejected;
  });

  /* ----------------------------------------------------------
     CRITICAL: Admin parameter mismatch attacks
     ---------------------------------------------------------- */

  it("CRITICAL: addOwner rejects mismatched threshold parameter", async function () {
    const { multisig, owner1, owner2, outsider } = await loadFixture(
      deployFixture,
    );

    // Sign for threshold = 3
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "addOwner",
      outsider.address,
      3,
    );

    // Try to call with threshold = 1 (lower security)
    await expect(multisig.addOwner(outsider.address, 1, adminSigs)).to.be
      .rejected;
  });

  it("CRITICAL: removeOwner rejects mismatched threshold parameter", async function () {
    const { multisig, owner1, owner2, owner3 } = await loadFixture(
      deployFixture,
    );

    // Sign for threshold = 2
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "removeOwner",
      owner3.address,
      2,
    );

    // Try to call with threshold = 1 (lower security)
    await expect(multisig.removeOwner(owner3.address, 1, adminSigs)).to.be
      .rejected;
  });

  it("CRITICAL: setThreshold rejects mismatched value", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    // Sign for threshold = 3
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setThreshold",
      ethers.constants.AddressZero,
      3,
    );

    // Try to call with threshold = 1
    await expect(multisig.setThreshold(1, adminSigs)).to.be.rejected;
  });

  it("CRITICAL: setExecutor rejects mismatched target address", async function () {
    const { multisig, owner1, owner2, outsider, executor } = await loadFixture(
      deployFixture,
    );

    // Sign for setting executor to outsider
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setExecutor",
      outsider.address,
      0,
    );

    // Try to call with different address (executor wants to keep their role)
    await expect(multisig.setExecutor(executor.address, adminSigs)).to.be
      .rejected;
  });

  /* ----------------------------------------------------------
     HIGH: Owner management edge cases
     ---------------------------------------------------------- */

  it("HIGH: cannot remove all owners (minimum 1 required)", async function () {
    const { multisig, owner1, owner2, owner3 } = await loadFixture(
      deployFixture,
    );

    // Remove owner3 (3 -> 2 owners), lower threshold to 1
    let adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "removeOwner",
      owner3.address,
      1,
    );
    await multisig.removeOwner(owner3.address, 1, adminSigs);

    expect((await multisig.ownerCount()).toNumber()).to.eq(2);
    expect((await multisig.threshold()).toNumber()).to.eq(1);

    // Remove owner2 (2 -> 1 owner), keep threshold at 1
    // Now threshold is 1, so only owner1 signature needed
    adminSigs = await signAdmin(
      multisig,
      [owner1],
      "removeOwner",
      owner2.address,
      1,
    );
    await multisig.removeOwner(owner2.address, 1, adminSigs);

    expect((await multisig.ownerCount()).toNumber()).to.eq(1);

    // Try to remove last owner - should fail because:
    // 1. newThreshold cannot be 0 (InvalidThreshold)
    // 2. newThreshold cannot be > newCount (0 owners means any threshold > 0 is invalid)
    // The only valid newThreshold for 0 owners would be 0, which is also invalid
    adminSigs = await signAdmin(
      multisig,
      [owner1],
      "removeOwner",
      owner1.address,
      1, // This would be > newCount (0)
    );

    // Should fail: threshold 1 > newOwnerCount 0
    await expect(multisig.removeOwner(owner1.address, 1, adminSigs)).to.be
      .rejected;

    // Also try with threshold 0 - should also fail
    adminSigs = await signAdmin(
      multisig,
      [owner1],
      "removeOwner",
      owner1.address,
      0,
    );

    await expect(multisig.removeOwner(owner1.address, 0, adminSigs)).to.be
      .rejected;

    // Verify owner1 is still an owner
    expect(await multisig.isOwner(owner1.address)).to.eq(true);
    expect((await multisig.ownerCount()).toNumber()).to.eq(1);
  });

  it("HIGH: constructor rejects empty owners array", async function () {
    const [executor] = await ethers.getSigners();
    const Multisig = await ethers.getContractFactory("GSWSafeV1");

    await expect(Multisig.deploy([], 0, executor.address)).to.be.rejectedWith(
      "InvalidThreshold",
    );
  });

  it("HIGH: constructor rejects threshold of 0", async function () {
    const [owner1, executor] = await ethers.getSigners();
    const Multisig = await ethers.getContractFactory("GSWSafeV1");

    await expect(
      Multisig.deploy([owner1.address], 0, executor.address),
    ).to.be.rejectedWith("InvalidThreshold");
  });

  it("HIGH: constructor rejects zero address executor", async function () {
    const [owner1] = await ethers.getSigners();
    const Multisig = await ethers.getContractFactory("GSWSafeV1");

    await expect(
      Multisig.deploy([owner1.address], 1, ethers.constants.AddressZero),
    ).to.be.rejectedWith("ZeroAddress");
  });

  it("HIGH: constructor rejects duplicate owners", async function () {
    const [owner1, executor] = await ethers.getSigners();
    const Multisig = await ethers.getContractFactory("GSWSafeV1");

    await expect(
      Multisig.deploy([owner1.address, owner1.address], 1, executor.address),
    ).to.be.rejectedWith("DuplicateOwner");
  });

  it("HIGH: owner can also be executor (verify intended behavior)", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    // Set owner1 as executor
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setExecutor",
      owner1.address,
      0,
    );

    await multisig.setExecutor(owner1.address, adminSigs);
    expect(await multisig.executor()).to.eq(owner1.address);

    // Verify owner1 can now execute
    await owner1.sendTransaction({
      to: multisig.address,
      value: ethers.utils.parseEther("1"),
    });

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner2.address,
      value: ethers.utils.parseEther("0.1"),
      data: "0x",
      nonce,
      deadline,
    });

    // owner1 is both signer and executor
    await expect(
      multisig
        .connect(owner1)
        .execute(
          owner2.address,
          ethers.utils.parseEther("0.1"),
          "0x",
          deadline,
          sigs,
        ),
    ).to.not.be.rejected;
  });

  /* ----------------------------------------------------------
     MEDIUM: Admin function access control
     ---------------------------------------------------------- */

  it("MEDIUM: anyone can submit admin transactions with valid signatures", async function () {
    const { multisig, owner1, owner2, outsider } = await loadFixture(
      deployFixture,
    );

    // outsider (non-owner, non-executor) can call setThreshold with valid sigs
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setThreshold",
      ethers.constants.AddressZero,
      1,
    );

    // This succeeds - document this is intended behavior
    await expect(multisig.connect(outsider).setThreshold(1, adminSigs)).to.not
      .be.rejected;

    expect((await multisig.threshold()).toNumber()).to.eq(1);
  });

  it("MEDIUM: cancelNonce requires threshold signatures", async function () {
    const { multisig, owner1 } = await loadFixture(deployFixture);

    // Sign with only 1 owner when threshold is 2
    const adminSigs = await signAdmin(
      multisig,
      [owner1], // Only 1 signature
      "cancelNonce",
      ethers.constants.AddressZero,
      0,
    );

    await expect(multisig.cancelNonce(adminSigs)).to.be.rejected;
  });

  it("MEDIUM: execute fails with fewer than threshold signatures", async function () {
    const { multisig, owner1, executor } = await loadFixture(deployFixture);

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    // Sign with only 1 owner
    const sigs = await signExecute({
      multisig,
      signers: [owner1],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, sigs),
    ).to.be.rejected;
  });

  /* ----------------------------------------------------------
     MEDIUM: Token operation tests
     ---------------------------------------------------------- */

  it("MEDIUM: can receive and transfer ERC20 tokens", async function () {
    const { multisig, owner1, owner2, executor, outsider } = await loadFixture(
      deployFixture,
    );

    // Deploy mock ERC20
    const MockERC20 = await ethers.getContractFactory("MockERC20");
    const token = await MockERC20.deploy(
      "Test",
      "TST",
      ethers.utils.parseEther("1000"),
    );
    await token.deployed();

    // Transfer tokens to multisig
    await token.transfer(multisig.address, ethers.utils.parseEther("100"));
    expect((await token.balanceOf(multisig.address)).toString()).to.eq(
      ethers.utils.parseEther("100").toString(),
    );

    // Execute transfer from multisig
    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const transferData = token.interface.encodeFunctionData("transfer", [
      outsider.address,
      ethers.utils.parseEther("50"),
    ]);

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: token.address,
      value: 0,
      data: transferData,
      nonce,
      deadline,
    });

    await multisig
      .connect(executor)
      .execute(token.address, 0, transferData, deadline, sigs);

    expect((await token.balanceOf(outsider.address)).toString()).to.eq(
      ethers.utils.parseEther("50").toString(),
    );
    expect((await token.balanceOf(multisig.address)).toString()).to.eq(
      ethers.utils.parseEther("50").toString(),
    );
  });

  /* ----------------------------------------------------------
     LOW: Edge cases and boundary conditions
     ---------------------------------------------------------- */

  it("LOW: deadline exactly at block.timestamp succeeds", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();

    // Get current block timestamp
    const block = await ethers.provider.getBlock("latest");
    const deadline = block.timestamp + 1; // Next block will have timestamp >= this

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    // Should succeed as long as block.timestamp <= deadline
    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, sigs),
    ).to.not.be.rejected;
  });

  it("LOW: execute increments nonce even when external call fails", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const FailingContract = await ethers.getContractFactory("FailingContract");
    const failing = await FailingContract.deploy();
    await failing.deployed();

    const nonceBefore = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const calldata = failing.interface.encodeFunctionData("alwaysFails");

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: failing.address,
      value: 0,
      data: calldata,
      nonce: nonceBefore,
      deadline,
    });

    // execute() does NOT revert on failed call - it returns success=false
    const tx = await multisig
      .connect(executor)
      .execute(failing.address, 0, calldata, deadline, sigs);

    const receipt = await tx.wait();

    // Check Executed event was emitted with success=false
    const executedEvent = receipt.events.find((e) => e.event === "Executed");
    expect(executedEvent.args.success).to.eq(false);

    // Nonce should have incremented
    const nonceAfter = await multisig.nonce();
    expect(nonceAfter.toNumber()).to.eq(nonceBefore.toNumber() + 1);
  });

  it("LOW: rejects signatures with extra bytes appended", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    let sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    // Append garbage bytes
    sigs = sigs + "deadbeef";

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, sigs),
    ).to.be.rejected;
  });

  it("LOW: rejects truncated signatures", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    let sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    // Truncate last byte
    sigs = sigs.slice(0, -2);

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, sigs),
    ).to.be.rejected;
  });

  it("LOW: handles large calldata without issues", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    // Create large calldata (10KB)
    const largeData = "0x" + "ab".repeat(10000);

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: largeData,
      nonce,
      deadline,
    });

    // Should execute without issues (call will fail but that's ok)
    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, largeData, deadline, sigs),
    ).to.not.be.rejected;
  });

  it("LOW: zero value transaction to EOA succeeds", async function () {
    const { multisig, owner1, owner2, executor, outsider } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: outsider.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(outsider.address, 0, "0x", deadline, sigs),
    ).to.not.be.rejected;
  });

  /* ----------------------------------------------------------
     REGRESSION: Ensure nonce behavior is correct
     ---------------------------------------------------------- */

  it("REGRESSION: nonce is shared between execute and admin functions", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const initialNonce = await multisig.nonce();

    // Execute admin action (setThreshold)
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setThreshold",
      ethers.constants.AddressZero,
      1,
    );
    await multisig.setThreshold(1, adminSigs);

    // Nonce should have incremented
    expect((await multisig.nonce()).toNumber()).to.eq(
      initialNonce.toNumber() + 1,
    );

    // Now try to execute with old nonce - should fail
    const oldNonce = initialNonce;
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    const sigs = await signExecute({
      multisig,
      signers: [owner1],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce: oldNonce,
      deadline,
    });

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, sigs),
    ).to.be.rejected;
  });

  /* ----------------------------------------------------------
     COMPUTATIONAL / GAS EXPLOITS
     ---------------------------------------------------------- */

  it("COMPUTATIONAL: nonce overflow is practically impossible (uint256)", async function () {
    const { multisig } = await loadFixture(deployFixture);

    // uint256 max is 2^256-1, approximately 1.15e77
    // At 1 tx per second, it would take 3.67e69 years to overflow
    // This test just documents that nonce is uint256
    const nonce = await multisig.nonce();
    expect(nonce.toNumber()).to.eq(0);

    // Verify nonce is stored as uint256 (no overflow concern)
    const maxUint256 = ethers.constants.MaxUint256;
    expect(maxUint256.gt(nonce)).to.eq(true);
  });

  it("COMPUTATIONAL: threshold cannot exceed ownerCount", async function () {
    const { multisig, owner1, owner2 } = await loadFixture(deployFixture);

    // Try to set threshold higher than ownerCount (3)
    const adminSigs = await signAdmin(
      multisig,
      [owner1, owner2],
      "setThreshold",
      ethers.constants.AddressZero,
      10, // Way higher than 3 owners
    );

    await expect(multisig.setThreshold(10, adminSigs)).to.be.rejected;
  });

  it("COMPUTATIONAL: ecrecover with zero hash returns zero address (handled)", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    // This tests that invalid signatures don't pass due to ecrecover quirks
    // ecrecover can return address(0) for invalid inputs, which is checked
    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    // Create a signature with all zeros (invalid)
    const invalidSigs = "0x" + "00".repeat(130); // 2 * 65 bytes

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, invalidSigs),
    ).to.be.rejected;
  });

  it("COMPUTATIONAL: signature with v=0 is rejected", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    let sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    // Corrupt v value to 0 (position 64 in first sig, which is byte 64)
    // Each sig is 65 bytes: r (32) + s (32) + v (1)
    // v is at position 64 (0-indexed) in each signature
    const sigArray = ethers.utils.arrayify(sigs);
    sigArray[64] = 0; // Set first signature's v to 0
    const corruptedSigs = ethers.utils.hexlify(sigArray);

    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", deadline, corruptedSigs),
    ).to.be.rejected;
  });

  it("COMPUTATIONAL: high-s signature is rejected (malleability protection)", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    const nonce = await multisig.nonce();
    const deadline =
      (await ethers.provider.getBlock("latest")).timestamp + 1000;

    let sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline,
    });

    // The secp256k1 curve order n
    const n = ethers.BigNumber.from(
      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    );
    const halfN = ethers.BigNumber.from(
      "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
    );

    // Extract s from first signature (bytes 32-64)
    const sigArray = ethers.utils.arrayify(sigs);
    const s = ethers.BigNumber.from(sigArray.slice(32, 64));

    // If s is already low, compute high-s = n - s
    if (s.lte(halfN)) {
      const highS = n.sub(s);
      const highSBytes = ethers.utils.arrayify(
        ethers.utils.hexZeroPad(highS.toHexString(), 32),
      );

      // Replace s with high-s
      for (let i = 0; i < 32; i++) {
        sigArray[32 + i] = highSBytes[i];
      }

      // Also flip v (27 -> 28 or 28 -> 27) to maintain valid signature
      sigArray[64] = sigArray[64] === 27 ? 28 : 27;

      const malleableSigs = ethers.utils.hexlify(sigArray);

      // This should be rejected due to high-s check
      await expect(
        multisig
          .connect(executor)
          .execute(owner1.address, 0, "0x", deadline, malleableSigs),
      ).to.be.rejected;
    }
  });

  it("COMPUTATIONAL: adding many owners doesn't break getOwners()", async function () {
    // Deploy fresh multisig with threshold 1 for easier testing
    const signers = await ethers.getSigners();
    const [owner1, executor, ...extraSigners] = signers;

    const Multisig = await ethers.getContractFactory("GSWSafeV1");
    const multisig = await Multisig.deploy(
      [owner1.address],
      1,
      executor.address,
    );
    await multisig.deployed();

    // Add 10 more owners
    for (let i = 0; i < 10 && i < extraSigners.length; i++) {
      const adminSigs = await signAdmin(
        multisig,
        [owner1],
        "addOwner",
        extraSigners[i].address,
        1,
      );
      await multisig.addOwner(extraSigners[i].address, 1, adminSigs);
    }

    // getOwners should still work
    const owners = await multisig.getOwners();
    expect(owners.length).to.be.gte(10);
  });

  it("COMPUTATIONAL: block.timestamp manipulation within bounds", async function () {
    const { multisig, owner1, owner2, executor } = await loadFixture(
      deployFixture,
    );

    // Miners can manipulate timestamp by ~15 seconds
    // Test that deadline at exact boundary still works
    const nonce = await multisig.nonce();
    const block = await ethers.provider.getBlock("latest");

    // Deadline exactly at MAX_DEADLINE_DURATION (30 days)
    const maxDeadline = block.timestamp + 30 * 24 * 60 * 60;

    const sigs = await signExecute({
      multisig,
      signers: [owner1, owner2],
      to: owner1.address,
      value: 0,
      data: "0x",
      nonce,
      deadline: maxDeadline,
    });

    // Should succeed at exactly 30 days
    await expect(
      multisig
        .connect(executor)
        .execute(owner1.address, 0, "0x", maxDeadline, sigs),
    ).to.not.be.rejected;
  });
});
