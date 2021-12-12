using System.ComponentModel;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthenticationApi.Entities
{
    public class User: AuditedEntity
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Username { get; set; }
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public UserType UserType { get; set; }
        [NotMapped]
        public string Password { get; set; }

    }
    public enum UserType
    {
        [Description("Unknown")]
        Unknown = 0,
        [Description("Administrator")]
        Administrator = 1,
        [Description("Admin")]
        Admin = 2,
        [Description("Customer")]
        Customer = 3
    }
}
