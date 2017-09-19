/*
David Ungar -- Spring 2017 Master's Project
Program to extract usefull data from the activity logs of a corporation.
Data is converted into Objects then sorted based on user.
It then generates Strings of #'s that correspond to certain activities. These are partitioned into weeks to allow "Hidden Markov" analysis to detect malicious insiders.
*/

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Date;
import java.util.Calendar;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Collections;
import java.text.SimpleDateFormat;

public class ExtractTest{
	public static void main(String[] args){
		
		CreateEmployeeArray("psychometric.csv");
		GetEmployeeActivities();
	    SortActivities();
		PrintMap();
		CreateCSVstring();
		
		
	}
	
	
	
	
	
	
	
	public static void CreateEmployeeArray(String fileName){
		
        //Delimiter used in CSV file
	    final String COMMA_DELIMITER = ",";
		numEmp = 0;
        		
		BufferedReader fileReader = null;
     
        try {
        	
            String line = "";
            
            //Create the file reader
            fileReader = new BufferedReader(new FileReader(fileName));
            
            //Read the CSV file header to skip it
            fileReader.readLine();
            
            //Read the file line by line starting from the second line
            while ((line = fileReader.readLine()) != null) {
                //Get all tokens available in line
                String[] tokens = line.split(COMMA_DELIMITER);
                if (tokens.length > 0) {
                	//Append a new row in the psychometrics 2D arraylist
					//Also add a new map pair with ID as the key and an Activity arraylist as the value 
					//Finally increment numEmp to keep track of the # of employees
					
					psychometrics.add(tokens);
					
					empActMap.put(tokens[1], new ArrayList<Activity>());
					
					numEmp++;
					
				}
            }
        }
		//Check for errors in the excecution
        catch (Exception e) {
        	System.out.println("Error in CsvFileReader !!!");
            e.printStackTrace();
        } finally {
            try {
                fileReader.close();
            } catch (IOException e) {
            	System.out.println("Error while closing fileReader !!!");
                e.printStackTrace();
            }
        }		
	}
	

	
	
	public static void GetEmployeeActivities(){
		//Call method for each file, to parse through each and generate Activity Objects to append to the employee ArrayList in the hashmap empActMap
		ParseDevice("deviceTest.csv");	
		ParseHttp("httpTest.csv");
		ParseLogon("logonTest.csv");
		ParseEmail("emailTest.csv");
		ParseFile("fileTest.csv");
		
	}
	
	
	
	public static void ParseDevice(String fileName){
		//Delimiter used in CSV file
	    final String COMMA_DELIMITER = ",";
        		
		BufferedReader fileReader = null;
     
        try {
        	
            String line = "";
            
            //Create the file reader
            fileReader = new BufferedReader(new FileReader(fileName));
            
            //Read the CSV file header to skip it
            fileReader.readLine();
            
            //Read the file line by line starting from the second line
            while ((line = fileReader.readLine()) != null) {
                //Get all tokens available in line
                String[] tokens = line.split(COMMA_DELIMITER);
                if (tokens.length > 0) {
					SimpleDateFormat formatter = new SimpleDateFormat("M/d/yyyy h:mm:ss a");  //1/2/2010 7:21:00 AM
					//Parse the row into the fields of a "Device" Activity object
					String id = tokens[0];
		            Date date = formatter.parse(tokens[1]);
		            String user = tokens[2];
		            String pc = tokens[3];
					String activity = tokens[4];
					
					//Append that object to the appropriate ArrayList for that particular employee using the HashMap empActMap
					(empActMap.get(user)).add(new Device(id, date, user, pc, activity));
					
				}
            }	
		}
		
	
		//Check for errors in the excecution
        catch (Exception e) {
        	System.out.println("Error in CsvFileReader !!!");
            e.printStackTrace();
        } finally {
            try {
                fileReader.close();
            } catch (IOException e) {
            	System.out.println("Error while closing fileReader !!!");
                e.printStackTrace();
            }
        }			
	}
	
	public static void ParseHttp(String fileName){
		//Delimiter used in CSV file
	    final String COMMA_DELIMITER = ",";
        		
		BufferedReader fileReader = null;
     
        try {
        	
            String line = "";
            
            //Create the file reader
            fileReader = new BufferedReader(new FileReader(fileName));
            
            //Read the CSV file header to skip it
            fileReader.readLine();
			
            //Read the file line by line starting from the second line
            while ((line = fileReader.readLine()) != null) {
                //Get all tokens available in line
                String[] tokens = line.split(COMMA_DELIMITER);
                if (tokens.length > 0) {
					SimpleDateFormat formatter = new SimpleDateFormat("M/d/yyyy h:mm:ss a");  //1/2/2010 7:21:00 AM
					//Parse the row into the fields of an "Http" Activity object
					String id = tokens[0];
		            Date date = formatter.parse(tokens[1]);
		            String user = tokens[2];
		            String pc = tokens[3];
					String url = tokens[4];
		            String content = tokens[5];
					
					//Append that object to the appropriate ArrayList for that particular employee using the HashMap empActMap
					(empActMap.get(user)).add(new Http(id, date, user, pc, url, content));
					
				}
            }
        }
		//Check for errors in the excecution
        catch (Exception e) {
        	System.out.println("Error in CsvFileReader !!!");
            e.printStackTrace();
        } finally {
            try {
                fileReader.close();
            } catch (IOException e) {
            	System.out.println("Error while closing fileReader !!!");
                e.printStackTrace();
            }
        }			
	}
	
	public static void ParseLogon(String fileName){
		//Delimiter used in CSV file
	    final String COMMA_DELIMITER = ",";
        		
		BufferedReader fileReader = null;
     
        try {
        	
            String line = "";
            
            //Create the file reader
            fileReader = new BufferedReader(new FileReader(fileName));
            
            //Read the CSV file header to skip it
            fileReader.readLine();
			
            //Read the file line by line starting from the second line
            while ((line = fileReader.readLine()) != null) {
                //Get all tokens available in line
                String[] tokens = line.split(COMMA_DELIMITER);
                if (tokens.length > 0) {
					SimpleDateFormat formatter = new SimpleDateFormat("M/d/yyyy h:mm:ss a");  //1/2/2010 7:21:00 AM
					//Parse the row into the fields of a "Logon" Activity object
					String id = tokens[0];
		            Date date = formatter.parse(tokens[1]);
		            String user = tokens[2];
		            String pc = tokens[3];
					String activity = tokens[4];
					
					//Append that object to the appropriate ArrayList for that particular employee using the HashMap empActMap
					(empActMap.get(user)).add(new Logon(id, date, user, pc, activity));
					
				}
            }
        }
		//Check for errors in the excecution
        catch (Exception e) {
        	System.out.println("Error in CsvFileReader !!!");
            e.printStackTrace();
        } finally {
            try {
                fileReader.close();
            } catch (IOException e) {
            	System.out.println("Error while closing fileReader !!!");
                e.printStackTrace();
            }
        }			
	}
	
	public static void ParseEmail(String fileName){
		//Delimiter used in CSV file
	    final String COMMA_DELIMITER = ",";
        		
		BufferedReader fileReader = null;
     
        try {
        	
            String line = "";
            
            //Create the file reader
            fileReader = new BufferedReader(new FileReader(fileName));
            
            //Read the CSV file header to skip it
            fileReader.readLine();
			
            //Read the file line by line starting from the second line
            while ((line = fileReader.readLine()) != null) {
                //Get all tokens available in line
                String[] tokens = line.split(COMMA_DELIMITER);
                if (tokens.length > 0) {
					SimpleDateFormat formatter = new SimpleDateFormat("M/d/yyyy h:mm:ss a");  //1/2/2010 7:21:00 AM
					//Parse the row into the fields of an "Email" Activity object
					String id = tokens[0];
		            Date date = formatter.parse(tokens[1]);
		            String user = tokens[2];
		            String pc = tokens[3];
					String to = tokens[4];
					String cc = tokens[5];
					String bcc = tokens[6];
					String from = tokens[7];
					String size = tokens[8];
					String attachments = tokens[9];
					String content = tokens[10];
					
					//Append that object to the appropriate ArrayList for that particular employee using the HashMap empActMap
					(empActMap.get(user)).add(new Email(id, date, user, pc, to, cc, bcc, from, size, attachments, content));
					
				}
            }
        }
		//Check for errors in the excecution
        catch (Exception e) {
        	System.out.println("Error in CsvFileReader !!!");
            e.printStackTrace();
        } finally {
            try {
                fileReader.close();
            } catch (IOException e) {
            	System.out.println("Error while closing fileReader !!!");
                e.printStackTrace();
            }
        }			
	}
	
	public static void ParseFile(String fileName){
		//Delimiter used in CSV file
	    final String COMMA_DELIMITER = ",";
        		
		BufferedReader fileReader = null;
     
        try {
        	
            String line = "";
            
            //Create the file reader
            fileReader = new BufferedReader(new FileReader(fileName));
            
            //Read the CSV file header to skip it
            fileReader.readLine();
			
            //Read the file line by line starting from the second line
            while ((line = fileReader.readLine()) != null) {
                //Get all tokens available in line
                String[] tokens = line.split(COMMA_DELIMITER);
                if (tokens.length > 0) {
					SimpleDateFormat formatter = new SimpleDateFormat("M/d/yyyy h:mm:ss a");  //1/2/2010 7:21:00 AM
					//Parse the row into the fields of a "File" Activity object
					String id = tokens[0];
		            Date date = formatter.parse(tokens[1]);
		            String user = tokens[2];
		            String pc = tokens[3];
					String filename = tokens[4];
					String content = tokens[5];
					
					//Append that object to the appropriate ArrayList for that particular employee using the HashMap empActMap
					(empActMap.get(user)).add(new File(id, date, user, pc, filename, content));
					
				}
            }
        }
		//Check for errors in the excecution
        catch (Exception e) {
        	System.out.println("Error in CsvFileReader !!!");
            e.printStackTrace();
        } finally {
            try {
                fileReader.close();
            } catch (IOException e) {
            	System.out.println("Error while closing fileReader !!!");
                e.printStackTrace();
            }
        }			
	}
	
	
	
	
	
	
	
	public static void SortActivities(){
		for (ArrayList<Activity> list : empActMap.values()){
			Collections.sort(list);
		}	
	}
	
	
	
	public static void PrintMap(){
		try{
			PrintWriter writer = new PrintWriter("out.txt", "UTF-8");
			//Print psychometrics
			for (String[] arr : psychometrics){
				writer.println(Arrays.toString(arr));
			}
			//Print # of employees
			writer.println("There are " + numEmp + " employees.");
			//Print the whole set of keys. This will be a list of all the employee ID's
			writer.println((empActMap.keySet()).toString());
			//Print the whole set of values. This will be a list of all the activities
			writer.println((empActMap.values()).toString());
			writer.close();
		}
		catch(IOException e){
			System.out.println("Output file error!!!");
			e.printStackTrace();
		}	
	}
	
	
	
	
	public static void CreateCSVstring(){
		//Delimiter used in CSV file
		String COMMA_DELIMITER = ",";
		String NEW_LINE_SEPARATOR = "\n";
		
		FileWriter fileWriter1 = null;
		FileWriter fileWriter2 = null;
		
		try {
			fileWriter1 = new FileWriter("simpleSet.csv");
			fileWriter2 = new FileWriter("comprehensiveSet.csv");
		
			//Write the CSV file header
			fileWriter1.append("user");			
			//Add a new line separator after the header
			fileWriter1.append(NEW_LINE_SEPARATOR);
			//Write the CSV file header
			fileWriter2.append("user");			
			//Add a new line separator after the header
			fileWriter2.append(NEW_LINE_SEPARATOR);
			
			int week = 100;
			int earliestWeek = 100;
			int prevWeek;
			
			for(String uID : empActMap.keySet()){//Search through each user in the map to find the earliest week with an activity
				week = empActMap.get(uID).get(0).getWeek();
				if(week < earliestWeek){
					earliestWeek = week;//earliestWeek will be set for the earliest week in the log
				}
			}
			 
			
			for(String uID : empActMap.keySet()){//for each user in the map
				ArrayList<Activity> lst = empActMap.get(uID);//Get his Activity ArrayList
				
				fileWriter1.append(uID);//Fill first field with user ID
				fileWriter1.append(COMMA_DELIMITER);
				fileWriter2.append(uID);
				fileWriter2.append(COMMA_DELIMITER);
				
				week = earliestWeek;
				prevWeek = earliestWeek;
				
				for(Activity a : lst){//for each Activity in the user's ArrayList
					week = a.getWeek();
					int dif = week - prevWeek;
					if(dif < 0){dif += 52;}//for end of year cases
					for(int i = 0; i < dif; i++){//first check if this Activity begins a new week. If yes, partition.
						fileWriter1.append(COMMA_DELIMITER);
						fileWriter2.append(COMMA_DELIMITER);
						prevWeek = week;
					}
					
					//Next determine and record the int represents this particular activity (for simple and comprehensive sets)
					if(a instanceof Device){
						if(((Device)a).getActivity().compareToIgnoreCase("Connect") == 0){//connect usb
							fileWriter1.append("6 ");
							
							if(a.getDay() == 1 || a.getDay() == 7){//Weekend connect
								fileWriter2.append("15 ");
							}
							else if(a.getHour() < 8 || a.getHour() > 16){//weekday out of 8am-5pm
								fileWriter2.append("14 ");
							}
							else{//weekday btw 8am and 5pm
								fileWriter2.append("13 ");
							}
						}
						else{//disconnect usb
							fileWriter1.append("7 ");
							fileWriter2.append("16 ");
						}
					}
					else if(a instanceof Http){//website
						fileWriter1.append("5 ");
						fileWriter2.append("12 ");
					}
					else if(a instanceof Logon){
						if(((Logon)a).getActivity().compareToIgnoreCase("Logon") == 0){//logon
							fileWriter1.append("1 ");
							
							if(a.getDay() == 1 || a.getDay() == 7){//Weekend logon
								fileWriter2.append("3 ");
							}
							else if(a.getHour() < 8 || a.getHour() > 16){//weekday out of 8am-5pm
								fileWriter2.append("2 ");
							}
							else{//weekday btw 8am and 5pm
								fileWriter2.append("1 ");
							}
						}
						else{//logoff
							fileWriter1.append("2 ");
							fileWriter2.append("4 ");
						}
					}
					else if(a instanceof Email){//email
						fileWriter1.append("4 ");
						//all internal(10) or contains external(11)
						if (((Email)a).extRecipient()){fileWriter2.append("11 ");}
						else{fileWriter2.append("10 ");}
					}
					else if(a instanceof File){//file to usb
						fileWriter1.append("3 ");
						//exe(5) jpg(6) zip(7) txt(8) doc/pdf(9)
						String type = ((File)a).getFileType();
						if(type.compareToIgnoreCase("doc") == 0 || type.compareToIgnoreCase("pdf") == 0){fileWriter2.append("9 ");}
						else if(type.compareToIgnoreCase("txt") == 0){fileWriter2.append("8 ");}
						else if(type.compareToIgnoreCase("zip") == 0){fileWriter2.append("7 ");}
						else if(type.compareToIgnoreCase("jpg") == 0){fileWriter2.append("6 ");}
						else{fileWriter2.append("5 ");}
					}
					
				}
				
				fileWriter1.append(NEW_LINE_SEPARATOR);
				fileWriter2.append(NEW_LINE_SEPARATOR);
			}
		} catch (Exception e) {
			System.out.println("Error in CsvFileWriter !!!");
			e.printStackTrace();
		} finally {
			
			try {
				fileWriter1.flush();
				fileWriter1.close();
				fileWriter2.flush();
				fileWriter2.close();
			} catch (IOException e) {
				System.out.println("Error while flushing/closing fileWriter !!!");
                e.printStackTrace();
			}
		}
		
		
		
		
		
		
		
		
	}
	
	
	
	
	
	
	
	
	
	
	//Abstract class to represent a general activity. Corresponds to a row in a CSV file.
	//The 4 data fields common to all the files are declared here.
	public static abstract class Activity implements Comparable<Activity>{
		protected String id;
		protected Date date;
		protected String user;
		protected String pc;
		
		//Getter methods
		public String getID(){
			return id;
		}
		
		public Date getDate(){
			return date;
		}
		
		public int getWeek(){
			Calendar cal = Calendar.getInstance();
			cal.setTime(date);
			return cal.get(Calendar.WEEK_OF_YEAR);
		}
		
		public int getDay(){
			Calendar cal = Calendar.getInstance();
			cal.setTime(date);
			return cal.get(Calendar.DAY_OF_WEEK);
		}
		
		public int getHour(){
			Calendar cal = Calendar.getInstance();
			cal.setTime(date);
			return cal.get(Calendar.HOUR_OF_DAY);
		}
		
		public String getUser(){
			return user;
		}
		
		public String getPC(){
			return pc;
		}
		
		@Override
		public int compareTo(Activity act){
			return getDate().compareTo(act.getDate());
		}
		
	}
	
	//The Activity object representing a row from device.csv
	public static class Device extends Activity{		
		//Data fields above that which are inherited from "Activity" 
		private String activity;
		
		//Constructor
		public Device (String id, Date date, String user, String pc, String activity){
			this.id = id;
			this.date = date;
			this.user = user;
			this.pc = pc;
			this.activity = activity;
		}
		
		//Getter method
		public String getActivity(){
			return activity;
		}
		
		//Overriding the toString() method to print object info
		@Override
		public String toString(){
			return "\nDevice Activity:\n id: " + id + "\n date: " + date.toString() + "\n user: " + user + "\n pc: " + pc + "\n activity: " + activity + "\n\n";
		}
	}
	
	//The Activity object representing a row from http.csv
	public static class Http extends Activity{
		//Data fields above that which are inherited from "Activity"
		private String url;
		private String content;
		
		//Constructor
		public Http (String id, Date date, String user, String pc, String url, String content){
			this.id = id;
			this.date = date;
			this.user = user;
			this.pc = pc;
			this.url = url;
			this.content = content;
		}
		
		//Getter methods
		public String getURL(){
			return url;
		}
		
		public String getContent(){
			return content;
		}
		
		//Overriding the toString() method to print object info
		@Override
		public String toString(){
			return "\nHttp Activity:\n id: " + id + "\n date: " + date.toString() + "\n user: " + user + "\n pc: " + pc + "\n url: " + url + "\n content: " + content + "\n\n";
		}
	}
	
	//The Activity object representing a row from logon.csv
	public static class Logon extends Activity{
		//Data fields above that which are inherited from "Activity"
		private String activity;
		
		//Constructor
		public Logon (String id, Date date, String user, String pc, String activity){
			this.id = id;
			this.date = date;
			this.user = user;
			this.pc = pc;
			this.activity = activity;
		}
		
		//Getter methods
		public String getActivity(){
			return activity;
		}
		
		//Overriding the toString() method to print object info
		@Override
		public String toString(){
			return "\nLogon Activity:\n id: " + id + "\n date: " + date.toString() + "\n user: " + user + "\n pc: " + pc + "\n activity: " + activity + "\n\n";
		}
	}
	
	//The Activity object representing a row from email.csv
	public static class Email extends Activity{
		//Data fields above that which are inherited from "Activity"
		private String to;
        private String cc;
        private String bcc;
        private String from;
        private String size;
        private String attachments;
        private String content;
        
		//Constructor
		public Email (String id, Date date, String user, String pc, String to, String cc, String bcc, String from, String size, String attachments, String content){
			this.id = id;
			this.date = date;
			this.user = user;
			this.pc = pc;
			this.to = to;
			this.cc = cc;
			this.bcc = bcc;
			this.from = from;
			this.size = size;
			this.attachments = attachments;
			this.content = content;
		}
		
		//Getter methods
		public String getTo(){
			return to;
		}
		
		public String getCC(){
			return cc;
		}
		
		public String getBCC(){
			return bcc;
		}
		
		public String getFrom(){
			return from;
		}
		
		public String getSize(){
			return size;
		}
		
		public String getAttachments(){
			return attachments;
		}
		
		public String getContent(){
			return content;
		}
		
		//returns true if there is an external email address recipient
		public boolean extRecipient(){
			boolean isExternal = false;
			
			String[] recipients1 = to.split(";");
			ArrayList<String> allRecipients = new ArrayList<String>(Arrays.asList(recipients1));
			if(cc != null && !cc.isEmpty()){
				String[] recipients2 = cc.split(";");
				allRecipients.addAll(Arrays.asList(recipients2));
			}
			if(bcc != null && !bcc.isEmpty()){
				String[] recipients3 = bcc.split(";");
				allRecipients.addAll(Arrays.asList(recipients3));
			}
			
			for(int i = 0; i < allRecipients.size(); i++){
				String name = allRecipients.get(i);
				String parts[] = name.split("@");
				if(parts[1].compareToIgnoreCase("dtaa.com") != 0){
					isExternal = true;
					break;
				}	
			}
			return isExternal;
		}
		
		//Overriding the toString() method to print object info
		@Override
		public String toString(){
			return "\nEmail Activity:\n id: " + id + "\n date: " + date.toString() + "\n user: " + user + "\n pc: " + pc + "\n to: " + to + "\n cc: " 
			+ cc + "\n bcc: " + bcc + "\n from: " + from + "\n size: " + size + "\n attachments: " + attachments + "\n content: " + content + "\n\n";
		}
	}
	
	//The Activity object representing a row from file.csv
	public static class File extends Activity{
		//Data fields above that which are inherited from "Activity"
		private String filename;
		private String content;
		
		//Constructor
		public File (String id, Date date, String user, String pc, String filename, String content){
			this.id = id;
			this.date = date;
			this.user = user;
			this.pc = pc;
			this.filename = filename;
			this.content = content;
		}
		
		//Getter methods
		public String getFilename(){
			return filename;
		}
		
		public String getFileType(){
			String[] parts = filename.split("\\.");
			return parts[1];
		}
		
		public String getContent(){
			return content;
		}
		
		//Overriding the toString() method to print object info
		@Override
		public String toString(){
			return "\nFile Activity:\n id: " + id + "\n date: " + date.toString() + "\n user: " + user + "\n pc: " + pc + "\n filename: " + filename + "\n content: " + content + "\n\n";
		}
	}
	
	//Create an arraylist of String arrays to be filled by CSV file data 
    public static ArrayList<String[]> psychometrics = new ArrayList<String[]>();
	//Create a Hashmap to store employee ID's as the key mapped to an ArrayList of Activity objects
	public static HashMap<String, ArrayList<Activity> > empActMap = new HashMap<String, ArrayList<Activity> >();
	public static int numEmp;
	
	
	
} 










