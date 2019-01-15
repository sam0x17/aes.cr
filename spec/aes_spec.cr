require "./spec_helper"

STR1 = "hey this is a test and I would love to see you try this test out and really nail it so that we can see if things encrypt and yeah hey"

describe AES do
  it "initializes in 256 bit mode properly" do
    crypto = AES.new(256)
    crypto.key.size.should eq 32
    crypto.iv.size.should eq 32
  end

  it "initializes in 128 bit mode properly" do
    crypto = AES.new(128)
    crypto.key.size.should eq 16
    crypto.iv.size.should eq 16
  end

  it "round trips in 256 bit mode" do
    1000.times do
      crypto = AES.new(256)
      String.new(crypto.decrypt(crypto.encrypt(STR1.as_slice))).should eq STR1
    end
  end

  it "round trips in 128 bit mode" do
    1000.times do
      crypto = AES.new(128)
      String.new(crypto.decrypt(crypto.encrypt(STR1.as_slice))).should eq STR1
    end
  end

  it "varies encryption with each subsequent run (e.g. uses a nonce)" do
    crypto = AES.new
    prev = ""
    10.times do
      current = crypto.encrypt(STR1)
      current.should_not eq prev
      prev = current
    end
  end

  it "does not vary encryption when nonce_size is 0" do
    crypto = AES.new
    crypto.nonce_size = 0
    prev = ""
    10.times do
      current = crypto.encrypt(STR1)
      (current.should eq prev) if prev != ""
      prev = current
    end
  end

  it "supports various nonce sizes" do
    crypto = AES.new
    prev = ""
    old_size = 0
    100.times do
      while crypto.nonce_size == old_size
        crypto.nonce_size = (0..20).to_a.sample
      end
      old_size = crypto.nonce_size
      current = crypto.encrypt(STR1)
      current.should_not eq prev
      prev = current
    end
  end
end
