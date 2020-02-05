pragma solidity ^0.4.19;

import "./alt_bn128.sol";

contract OBFP {

	using alt_bn128 for *; 
	bytes public n_val = "0x00a2904487e49592a42890964f2a758ce58af027ba0fd68f6c9a5684a2d963b6af4127b91e0b9c084aeb0cd9cc81328433d8ed178e4c696c199e2a3d899f85b02f2d16023b57d06ada7e7ab46b49978063d739c9697b3b119783ba870132ac5bba37ccbd99b99a8188fcae7ccce24525dc03c50f78c7a043cc6c2589c90b3f717851d7de5f62d0eafe81aba1287d8e674750090e521589187613518892603dcb9ff37051616805e6fae9ff6185d8037711f2a8cf37db8ccad45fa4410d0e354a029268b22192fabaa45d0b6c72314682143f7e14603a40a9e314644b69cba10910dc651b5fa559a7df46a7758331b24e4ae1a050d280420a49b6119b6e61827749";
	uint constant v = 100;
	uint constant max = 64;
	struct Task{
        string f_des;
        uint h_s;
        string P_des;
        uint R_val;
        uint b_val;
        uint index;
		uint k_val;
        uint[max] V_val;
        uint h_val;
        uint[2] C_val;
        uint key_val;
        uint r_val;
        
    }

	address public user;
    address public worker;
    Task task;

    uint public i;
    uint public j;
    
    uint[2] public baseP;
    uint[2] public baseQ;
    uint private start;
	
	//constructor, automatically executed
	function OBFP(address user_address, address worker_address) public {
	//** add hard-coded values as neccessary here ***//
		user = user_address;
		worker = worker_address;
		baseP = peddersenBaseP();
        baseQ = peddersenBaseQ();
	}
	function peddersenBaseP() public view returns (uint[2] point) {
        bytes32 h = keccak256("P");
        alt_bn128.G1Point memory g1p = alt_bn128.uintToCurvePoint(uint(h));
        return [g1p.X, g1p.Y];
    }
    
    function peddersenBaseQ() public view returns (uint[2] point) {
        bytes32 h = keccak256("Q");
        alt_bn128.G1Point memory g1p = alt_bn128.uintToCurvePoint(uint(h));
        return [g1p.X, g1p.Y];
    }
	
	//function to submit the task
	function submitTask(string f_des, uint h_s, string P_des, uint R_val, uint b_val, uint[max] V_val) public  {
	    uint i;
	    task.f_des = f_des;
	    task.h_s = h_s;
	    task.P_des = P_des;
	    task.R_val = R_val;
	    task.b_val = b_val;
	    for(i=0; i< max; i++)
	    {
	        task.V_val[i] = V_val[i];
	    }
	}
	
	//function to get the task
	function getTask () public view returns(string f_des, uint h_s, string P_des, uint R_val, uint b_val, uint[max] V_val){
	    return (task.f_des, task.h_s, task.P_des, task.R_val, task.b_val, task.V_val);
	}
	
	//function to compute the commitment
	function computeCM(uint key_val, uint r_val) public view returns(uint[2] commitment){
	
	    alt_bn128.G1Point memory P_point;
	    alt_bn128.G1Point memory Q_point;
	    // Generate left point r * Q
        P_point.X = baseP[0];
        P_point.Y = baseP[1];
        alt_bn128.G1Point memory lf = alt_bn128.mul(P_point, r_val);
        
        
        Q_point.X = baseQ[0];
        Q_point.Y = baseQ[1];
        // Generate right point key * P
        alt_bn128.G1Point memory rt = alt_bn128.mul(Q_point, key_val);

        // Generate C = key * P + r * Q
        alt_bn128.G1Point memory C_point = alt_bn128.add(lf, rt);
        commitment[0] = C_point.X;
        commitment[1] = C_point.Y;
        return commitment;
        
	}
	
	//function to submit the commitment
	function submitCM(uint k_val, uint h_val, uint[2] C_val) public payable returns (bool){
	//** the function of submitCM **//
		require((msg.sender == worker) && (msg.value >= 2*k_val*v));
		
		task.k_val = k_val;
		task.h_val = h_val;

		for(i = 0; i <2; i++)
		{
		    task.C_val[i] = C_val[i];
		}
		return true;
	}
	
	//function to get the commitment
	function getCM() public view returns (uint k_val, uint h_val, uint[2] C_val){
	     
		 return(task.k_val, task.h_val, task.C_val);
         
    }
    
	//function to pay for the request
    function payRequest () public payable returns (bool){
        require((msg.sender == user) && (msg.value >= task.k_val*v));
        return true;
        
    }
	
	//function to submit the proof
	function submitProof(uint key_val, uint r_val) public returns (bool){
	    require(msg.sender == worker);
	    var (, commitment) = getCM();
	    if(verify(key_val, r_val, commitment))
	    {
	        task.key_val = key_val;
	        task.r_val = r_val;
	        msg.sender.transfer(task.k_val*v);
	        start = now; //now is an alias for block.timestamp, not really "now"
	    }
	    return true;
	    
	}
	
	//function to obtain the proof
	function getProof() public view returns (uint, uint){
	       require(msg.sender==user);
	      return (task.key_val, task.r_val);
	}
	
	//function to verify the proof
	function verify(uint key_val, uint r_val, uint[2] commitment) public view returns (bool){
	    alt_bn128.G1Point memory P_point;
	    alt_bn128.G1Point memory Q_point;
	    // Generate left point r * Q
        P_point.X = baseP[0];
        P_point.Y = baseP[1];
        alt_bn128.G1Point memory lf = alt_bn128.mul(P_point, r_val);
        
        
        Q_point.X = baseQ[0];
        Q_point.Y = baseQ[1];
        // Generate right point key * P
        alt_bn128.G1Point memory rt = alt_bn128.mul(Q_point, key_val);

        // Generate C = key * P + r * Q
        alt_bn128.G1Point memory C_point = alt_bn128.add(lf, rt);

        return (C_point.X == commitment[0] && C_point.Y == commitment[1]);
	}
	
	// function to submit claim proof
	function submitCP(uint d, uint c_d, uint pi1, bytes pi2) public returns (bool){
	    uint x_val;
	    if(msg.sender == user)
	    {
    	    
    	    if(pi1 == uint(keccak256(d,c_d))&&(rsaverify(toBytes(task.h_val),n_val,pi1,pi2,1)))
    	    {
    	           x_val = decrypt(c_d, task.key_val);
    	           for(j = 0; j < task.k_val; j++)
    	           {
    	               if(uint(keccak256(x_val)) == task.V_val[j])
    	               {
    	                   return false;
    	               }
    	           }
    	           msg.sender.transfer(2*task.k_val*v);
    	           return true;
    	        
    	    }
	    }
	    else if (msg.sender == worker)
	    {
	        if(now > start + 10 minutes)
	        {
	            msg.sender.transfer(2*task.k_val*v);
	        }
	    }
	}
	
	
	// function to both encrypt and decrypt text chunks using key
	function symmecrpto (uint[max] plaintext, uint key) private view returns (uint[max]){
	    uint l;
	    uint[max] ciphertext;
        for (l = 0; l < task.k_val; l++){
            ciphertext[l] = uint(keccak256(l, key)) ^ plaintext[l];
        }
        return ciphertext;
    }
    
    // function to decrypt only one text chunk using key
	function decrypt (uint plaintext, uint key) private view returns (uint){
	    uint ciphertext;
        ciphertext = uint(keccak256(1, key)) ^ plaintext;
        return ciphertext;
    }
	
	function toBytes(uint _num) public returns (bytes memory _ret) {
      assembly {
        _ret := mload(0x10)
        mstore(_ret, 0x20)
        mstore(add(_ret, 0x20), _num)
        }
    }
	
	function rsaverify(bytes msg, bytes n, uint e, bytes S, uint paddingScheme) public returns (bool) {
		uint len;
		assembly {
           len := calldatasize()
		}

        bytes memory req = new bytes(len - 4);
        bytes memory res = new bytes(32);

        uint status;

        assembly {
            let alen := len
            calldatacopy(req, 4, alen)
            call(sub(gas, 150), 5, 0, req, alen, add(res, 32), 32)
            =: status
        }

        if (status != 1)
          return false;

        return res[31] == 1;
     }
	 
}
