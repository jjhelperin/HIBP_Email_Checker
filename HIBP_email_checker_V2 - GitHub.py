import requests
from requests import RequestException
import pandas as pd
import time

# HIBP's API required fields
HIBP_URI = "https://haveibeenpwned.com/api/v3/breachedaccount/"
API_KEY = API_KEY
user_agent = "CAR HIBP Email Checker"
headers = {"hibp-api-key": API_KEY, "user-agent": user_agent}

pwned_emails = []       # lists of emails to make sure no duplicates are added.

bad_excel_rows = []     # Emails and rows that had errors when tried to request
                        # from HIBP's API

# DataFrame to store pwned Emails. Redefined in interate_over_emails
pwned_emails_df = pd.DataFrame()

# # Keeps track for which line to input the pwned emails data into pwned_emails_df.
# Cannot rely on index pwned_emails_df as that deals with a different excel/csv file.
# If append is True, set the row_low of pwned_emails_df to the last row of
# the content DataFrame and add one to it, as to not overwrite any existing data.
# This is done down below.
pwned_emails_df_row_log = 0

save_to_file_path = "/Users/jjhelperin/Desktop/CAR Internship/HIBP/Pwned Emails/Test.csv"

def iterate_over_csv(file_path_with_emails, content=None, append=False,\
    start_row=0, stop_row=0, lookup_file_path=None):
    '''
    Reads a CSV file_path and a start_row for which row to start processing 
    data on. The CSV file should be the All CAR Members list from Pardot.
 
    :param file_path_with_emails: The file path that contains the 
        emails to be checked.
    :param content: Either a list of headers if new CSV is 
        wanted as a result, otherwise, provide a file path 
        that will be used to append the results to. If a file path
        is provided, 'content' is then to be used in conjuction with 'append'.
        If 'content' is a file path and 'append' is True, the results of the
        program will be appended to the file provided by the file path. If
        append is False, a new CSV will be created and all of that file's 
        headers will be used as the fields to be found. If the latter is the
        case, be sure that the headers of the content file have the same exact
        headers as wherever the data associated with the email is coming from.
        Default is None, i.e. create a new CSV with all headers and data 
        associated with the emails within 'file_path_with_emails'.
    :param append: If 'append' is True, the program will append the results to 
        the file provided by content. If 'append' is False, the program will 
        create a new CSV with the file name specified by the global variable
        'save_to_file_path', but with the same headers as the file specified
        by content.
    :param start_row: The row to start processing data on in 
        email_file_path.
    :param stop_row: The row, inclusive, in the CSV file to stop processing data on.
    :param lookup_file_path: If the data associated with the emails
        exist in another file, pass the file path here. Should be used if for
        example, 'file_path_with_emails' only has a specific list of emails to 
        check, but the data associated with the emails exists within a 
        different file.
    '''
    
    global pwned_emails_df, pwned_emails_df_row_log, save_to_file_path

    if start_row < 0:
        error_msg = "'start_row cannot be negative."
        raise ValueError(error_msg)
    
    if stop_row < 0 or stop_row < start_row:
        error_msg = "'stop_row cannot be negative or less than 'start_row'."
        raise ValueError(error_msg)


    # Type check on 'content' with value of 'append'
    if type(content) is list and append == True:
        error_msg = "Append cannot be True when 'content' type='list'. 'append' " +\
            "should only be True if 'content' is a file path (type='str') that "+\
            "the results be appended to."
        print("Type of 'content':", type(content), "'append':", append)
        raise TypeError(error_msg)

    # DataFrame that contains the emails to be processed
    email_df = pd.read_csv(file_path_with_emails)
    
    # Use a list passed as a parameter to be the headers of redefine
    # pwned_emails_df or use your own file.
    if type(content) is list:
        pwned_emails_df = pd.DataFrame(columns=content)
    elif type(content) is str:
        content_df = pd.read_csv(content)

        # Append to file path specified by content and make
        # pwned_emails_df_row_log equal to the last row of
        # the content DataFrame and add one to it, as to not 
        # overwrite any existing data.
        if append:
            pwned_emails_df = pd.read_csv(content)
            if len(content_df.index) != 0:
                pwned_emails_df_row_log = content_df.index[-1] + 1
            save_to_file_path = content
        
        # Make new CSV file with header columns equal 
        # to the file's header columns.
        else:
            pwned_emails_df = pd.DataFrame(columns=content_df.columns)
    elif type(content) is type(None):
        pwned_emails_df = pd.DataFrame(columns=email_df.columns)
    else:
        error_msg = "You must specify a list a file_path, or None for argument 'content'"
        print(type(content))
        raise TypeError(error_msg)
    
    # DataFrame that contains the data associated with the emails if
    # file_path_with_emails, or subsequently, email_df doesn't already 
    # have them.
    lookup_df = pd.read_csv(lookup_file_path) if lookup_file_path else None

    # Use index + 1 since pandas DataFrames takes away header rows and starts at 0.
    for index in email_df.index:

        # Used if you are starting in the middle of the CSV email file.
        if index + 1 >= start_row:

            # Saves the pwned emails in a CSV in increments in order
            # to not lose most of the progress the program has made.
            if index % 50 == 0:
                pwned_emails_to_csv()
            
            try:
                process_email(index, email_df.at[index, "Email"],\
                    email_df, lookup_df)
            except:
                # Append the current row to list to check manually later
                # and save pwned emails.
                bad_excel_rows.append("Email " + email_df.at[index, "Email"] +\
                    " at row: " + str(index + 1))
                pwned_emails_to_csv()
        
        if index + 1 == stop_row:
            return


def process_email(index, email, email_df, lookup_df):    
    '''
    Calls check_if_pwned. If True is returned, add email to pwned_emails and 
    add all data specified in content to DataFrame.
 
    :param index: The current row we are at in 'email_df'.
    :param email: The email we are processing.
    :param email_df: The DataFrame that contains the emails to be 
        processed.
    :param lookup_df: The DataFrame, if not None, that contains the
        data associated with the email if 'email_df' does not have the 
        data.
    '''

    global pwned_emails_df, pwned_emails_df_row_log
    pwned = check_if_pwned(email)
    
    if pwned:
        print("Pwned email:", email)

        if email not in pwned_emails:
            pwned_emails.append(email)
        
        for header in pwned_emails_df.columns:
            try:
                # If lookup_df is not None, use it to find the data within
                # the specified header columns.
                if lookup_df is not None:
                    lookup_row_df = lookup_df[lookup_df["Email"] == email]
                    if not lookup_row_df.empty:
                        pwned_emails_df.at[pwned_emails_df_row_log, header] = \
                            lookup_row_df[header].values[0]
                    else:
                        pwned_emails_df.loc[pwned_emails_df_row_log, header] = \
                            "EMAIL DNE IN LOOKUP FILE"
                # If the data associated with the email is in the same file and
                # row as where you are getting the email from.
                else:
                    pwned_emails_df.at[pwned_emails_df_row_log, header] = \
                        email_df.at[index, header]
            except Exception as e:
                print("Caught Exception:", e)
                # Append the current row to list to check manually later
                bad_excel_rows.append("Email " + email + " at row: " + str(index + 1))
                pwned_emails_df.at[pwned_emails_df_row_log, header] = "CAUGHT EXCEPTION"
        
        # Increment pwned_emails_df_row_log to add a new row in the DataFrame.
        pwned_emails_df_row_log += 1


def check_if_pwned(email):
    '''
    Method to check if the email has been pwned (Response status_codde = 200),
    if email has not been pwned (Response status_code = 404), or something went
    wrong. Either an error (Response status_code = 400 or 403), or too many 
    requests have been made (Response status_code = 429), and we must wait 
    until we can make another request to HIBP’s API at: 
    https://haveibeenpwned.com/API/v3.

    :param email: The email to be checked if pwned.
    '''

    time.sleep(2.25) # API says to make a call every 1.5 seconds, but that still
                    # receives a response of 429, "Too many Requests." So, the
                    # happy medium is about 2.25 seconds, since we would only 
                    # have to wait 1 second if too many requests were made. 
    while True:
        try:
            response = requests.get(url=HIBP_URI + email, headers=headers)
            resp_code = response.status_code
            print(response.json())
            if resp_code == 200:    # Pwned Email
                return True
            elif resp_code == 429:  # Too Many Request
                raise ConnectionError(resp_code, response.reason)
            else:
                if resp_code != 404: # 404 = Not pwned, anything else = error occured
                    print("Response Code:", resp_code, "\t", "Reason:", response.reason)
                    bad_excel_rows.append("Email: " + email + "\tReason: " + response.reason)
                return False
        except ConnectionError as e:
            print("Caught Exception:", e)
            print("Retry After: " + response.headers['Retry-After'] + " seconds")
            sleep_time = float(response.headers['Retry-After'])
            time.sleep(sleep_time)


def pwned_emails_to_csv():
    '''
    Converts pwned_emails_df DataFrame that contains the pwned emails that have
    been found to a CSV file, then prints the current row we are at within the
    CSV file that contains the emails to be processed.
    '''

    pwned_emails_df.to_csv(save_to_file_path, index=False)
    print("Making CSV file:")


def main():
    '''
    Specifies the content to be passed into iterate_over_csv, calls
    Iterate_over_csv with file paths and start row, and prints out the 
    emails and row numbers of the rows in the CSV that made a bad
    request to HIBP’s API (Response status_code = 400 or 403).
    '''

    file_with_emails = "/Users/jjhelperin/Desktop/CAR Internship/HIBP/Pwned Emails/All Pwned Emails - Master List.csv"
    
    content =  ["NRDS ID", "Last Name", "First Name", "Email",\
                "DRE License Number", "Office NRDS ID", "Office Name",\
                "Primary Association Name", "Primary Association NRDS ID"]
    
    #lookup_file_path = "/Users/username/Desktop/Lookup File Name.csv"
    
    iterate_over_csv(file_with_emails, content=content, stop_row=50)
    
    pwned_emails_to_csv()

    bad_excel_rows_df = pd.DataFrame(bad_excel_rows, columns=["Bad Excel Rows"])

    bad_excel_rows_df.to_csv("/Users/username/Desktop/Bad Excel Rows.csv")


if __name__ == "__main__":
    main()