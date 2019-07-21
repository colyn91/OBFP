pragma solidity ^0.4.19;

import "./alt_bn128.sol";

contract OBPay {

	using alt_bn128 for *; 

	uint constant k = 60;
	struct Task{
        string f_des;
        uint256 h_s;
        string P_des;
        uint256 R_val;
        uint256 b_val;
        uint256 index;
        uint256[k] T_val;
        uint256[k] P2_val;
        uint256[k] h_val;
        uint256[2] C_val;
        uint256 key_val;
        uint256 r_val;
        
    }
    
    struct CM{
        uint256[k] h_val;
        uint256[2] C_val;
    }
    
	uint constant v = 100;
	uint constant v_f= k * v;
	uint constant v_g = 2 * k * v;
	address public user;
    address public worker;
    Task task;

    uint public i;
    uint public j;
    
    uint256[2] public baseP;
    uint256[2] public baseQ;
    uint256 private start;
	
	//constructor, automatically executed
	function OBPay(address user_address, address worker_address) public {
	//** add hard-coded values as neccessary here ***//
		user = user_address;
		worker = worker_address;
		baseP = peddersenBaseP();
        baseQ = peddersenBaseQ();
	}
	function peddersenBaseP() public view returns (uint256[2] point) {
        bytes32 h = keccak256("P");
        alt_bn128.G1Point memory g1p = alt_bn128.uintToCurvePoint(uint256(h));
        return [g1p.X, g1p.Y];
    }
    
    function peddersenBaseQ() public view returns (uint256[2] point) {
        bytes32 h = keccak256("Q");
        alt_bn128.G1Point memory g1p = alt_bn128.uintToCurvePoint(uint256(h));
        return [g1p.X, g1p.Y];
    }
	
	//function to submit the task
	function submitTask(string f_des, uint256 h_s, string P_des, uint256 R_val, uint256 b_val, uint256[k] T_val, uint256[k] P2_val ) public  {
	    task.f_des = f_des;
	    task.h_s = h_s;
	    task.P_des = P_des;
	    task.R_val = R_val;
	    task.b_val = b_val;
	    for(i = 0; i < k; i++)
	    {
	        task.T_val[i] = T_val[i];
	        task.P2_val[i] = P2_val[i];
	    }
	}
	
	//function to get the task
	function getTask () public view returns(string f_des, uint256 h_s, string P_des, uint256 R_val, uint256 b_val, uint256[k] T_val, uint256[k] P2_val){
	    return (task.f_des, task.h_s, task.P_des, task.R_val, task.b_val, task.T_val, task.P2_val);
	}
	
	//function to compute the commitment
	function computeCM(uint256 key_val, uint256 r_val) public view returns(uint256[2] commitment){
	
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
	function submitCM(uint256[k] h_val, uint256[2] C_val) public payable returns (bool){
	//** the function of submitCM **//
		require((msg.sender == worker) && (msg.value >= v_g));
		for(i = 0; i < k; i++)
		{
		    task.h_val[i] = h_val[i];
		}
		for(i = 0; i <2; i++)
		{
		    task.C_val[i] = C_val[i];
		}
		return true;
	}
	
	//function to get the commitment
	function getCM() public view returns (uint256[k] h_val, uint256[2] C_val){
	     
		 return(task.h_val, task.C_val);
         
    }
    
	//function to pay for the request
    function payRequest () public payable returns (bool){
        require((msg.sender == user) && (msg.value >= v_f));
        return true;
        
    }
	
	//function to submit the proof
	function submitProof(uint256 key_val, uint256 r_val) public returns (bool){
	    require(msg.sender == worker);
	    var (, commitment) = getCM();
	    if(verify(key_val, r_val, commitment))
	    {
	        task.key_val = key_val;
	        task.r_val = r_val;
	        msg.sender.transfer(v_f);
	        start = now; //now is an alias for block.timestamp, not really "now"
	    }
	    return true;
	    
	}
	
	//function to obtain the proof
	function getProof() public view returns (uint256, uint256){
	    

	      return (task.key_val, task.r_val);
	}
	
	//function to verify the proof
	function verify(uint256 key_val, uint256 r_val, uint256[2] commitment) public view returns (bool){
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
	function submitCP(uint256 c_val) public returns (bool){
	    uint256 x_val;
	    if(msg.sender == user)
	    {
    	    for(i = 0; i < k; i ++)
    	    {
    	        if(task.h_val[i] == uint256(keccak256(c_val)))
    	        {
    	           x_val = decrypt(c_val, task.key_val);
    	           for(j = 0; j < k; j++)
    	           {
    	               if(uint256(keccak256(x_val)) == task.P2_val[j])
    	               {
    	                   return false;
    	               }
    	           }
    	           msg.sender.transfer(v_g);
    	           return true;
    	        }
    	    }
	    }
	    else if (msg.sender == worker)
	    {
	        if(now > start + 10 minutes)
	        {
	            msg.sender.transfer(v_g);
	        }
	    }
	}
	
	// function to both encrypt and decrypt text chunks using key
	function symmecrpto (uint256[k] plaintext, uint256 key) private view returns (uint256[k]){
	    uint256 l;
	    uint256[k] ciphertext;
        for (l = 0; l < k; l++){
            ciphertext[l] = uint256(keccak256(l, key)) ^ plaintext[l];
        }
        return ciphertext;
    }
    
    // function to decrypt only one text chunk using key
	function decrypt (uint256 plaintext, uint256 key) private view returns (uint256){
	    uint256 ciphertext;
        ciphertext = uint256(keccak256(1, key)) ^ plaintext;
        return ciphertext;
    }

}
