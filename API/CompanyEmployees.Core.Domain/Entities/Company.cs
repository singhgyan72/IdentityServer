using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CompanyEmployees.Core.Domain.Entities
{
    public class Company
    {
        [Column("CompanyId")]
        public Guid Id { get; set; }

        [Required]
        [MaxLength(60)]
        public string? Name { get; set; }

        [Required]
        [MaxLength(60)]
        public string? Address { get; set; }

        public string? Country { get; set; }

        public ICollection<Employee>? Employees { get; set; }
    }
}
