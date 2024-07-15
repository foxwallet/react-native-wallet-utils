const path = require("path");
const axios = require("axios");
const fs = require("fs");
const { createHash } = require("crypto");

const baseUrl = "https://cdn-pkg.foxnb.net/app_image/static/aleo_params/";
const downloadUrl = "https://s3-us-west-1.amazonaws.com/mainnet.parameters";
const ignoreFiles = [
  ".DS_Store",
  "block.genesis",
  "genesis.metadata",
  "beta-h.metadata",
];
const dirPath = path.join(
  __dirname,
  "../fox-snarkvm/parameters/src/mainnet/resources"
);
const targetPath = path.join(__dirname, "../rust/src/aleo_params");

const files = fs.readdirSync(dirPath);

async function checkFile(filePath, checksum) {
  const exist = fs.existsSync(filePath);
  if (!fs.existsSync(filePath)) {
    return false;
  }
  const fileBuffer = fs.readFileSync(filePath);
  const hashSum = createHash("sha256");
  hashSum.update(fileBuffer);
  const hex = hashSum.digest("hex");
  return hex === checksum;
}

async function downloadFile(url, dest) {
  try {
    console.log("===> downloading url: ", url, dest);
    const response = await axios.get(url, {
      responseType: "stream",
    });

    const writer = fs.createWriteStream(dest);

    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on("finish", resolve);
      writer.on("error", reject);
    }).catch((err) => {
      console.log("err ", url, err);
    });
  } catch (err) {
    console.log("err ", url, err);
  }
}

const downloadFiles = async () => {
  for (let file of files) {
    console.log("===> process ", file);
    const source = `${dirPath}/${file}`;
    const target = `${targetPath}/${file}`;
    if (ignoreFiles.some((item) => file.startsWith(item))) {
      console.log("===> jump ", file);
      continue;
    }
    if (!file.endsWith(".metadata")) {
      console.log("===> copy ", file);

      fs.copyFileSync(source, target);
      continue;
    }
    const str = fs.readFileSync(source, "utf-8");
    const obj = JSON.parse(str);

    if (
      file.startsWith("power") ||
      file.startsWith("shifted") ||
      file.startsWith("neg")
    ) {
      const fileName = file.replace(".metadata", "");
      const fileFullName = `${fileName}.usrs.${obj.checksum.slice(0, 7)}`;
      const targetFilePath = `${targetPath}/${fileFullName}`;
      const fileCorrect = await checkFile(targetFilePath, obj.checksum);
      if (fileCorrect) {
        console.log("===> targetFile exist: ", targetFilePath);
        continue;
      }
      const url = `${downloadUrl}/${fileFullName}`;
      await downloadFile(url, targetFilePath);
      continue;
    }
    const fileName = file.replace(".metadata", "");
    const proverFileName = `${fileName}.prover.${obj.prover_checksum.slice(
      0,
      7
    )}`;
    const proverFilePath = `${targetPath}/${proverFileName}`;
    const proverUrl = `${downloadUrl}/${proverFileName}`;
    const proverFileCorrect = await checkFile(
      proverFilePath,
      obj.prover_checksum
    );
    if (proverFileCorrect) {
      console.log("===> targetFile exist: ", proverFilePath);
      continue;
    }
    await downloadFile(proverUrl, proverFilePath);
  }
};

async function main() {
  try {
    await downloadFiles();
  } catch (err) {
    console.log(err.message);
  }
}

main();
