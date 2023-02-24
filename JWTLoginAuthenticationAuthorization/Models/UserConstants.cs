namespace JWTLoginAuthenticationAuthorization.Models
{
    // We are not taking data from data base so we get data from constant
    public class UserConstants
    {
        public static List<UserModel> Users = new()
            {
                    new UserModel(){ Username="naeem",Password="naeem_admin",Role="Admin"}
            };
    }
}
